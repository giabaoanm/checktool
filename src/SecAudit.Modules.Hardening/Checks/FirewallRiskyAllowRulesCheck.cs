using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.Hardening.Checks;

/// <summary>
/// Walks every active inbound firewall rule and flags those that allow connections from
/// <i>any</i> remote address to a sensitive listening port.
///
/// <para>
/// Rules are stored as REG_SZ values under
/// <c>HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules</c>.
/// Each value is a pipe-delimited token list — the format Microsoft documents in
/// MS-FASP §2.2.2.1.4 ("Firewall Rule").
/// </para>
///
/// <para>
/// We treat a rule as <i>risky</i> when ALL of the following hold:
/// <list type="bullet">
///   <item><c>Action=Allow</c></item>
///   <item><c>Active=TRUE</c></item>
///   <item><c>Dir=In</c></item>
///   <item><c>LPort</c> matches a sensitive service (RDP/SMB/WinRM/RPC/MSSQL/Telnet/FTP/SSH/VNC/…)</item>
///   <item>No source restriction — <c>RA4</c>/<c>RA6</c> absent or any token is <c>*</c></item>
/// </list>
/// A rule that scopes the source to the LAN (<c>RA4=10.0.0.0/8</c>, <c>LocalSubnet</c>, etc.)
/// is intentionally <b>not</b> flagged — that's the standard SOC posture.
/// </para>
///
/// <para>
/// Severity is per-port: <c>High</c> for the lateral-movement classics (3389/445/5985/5986)
/// and <c>Medium</c> for everything else. All matches collapse into a single finding so the
/// admin sees the full picture in one row.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallRiskyAllowRulesCheck : ICheck
{
    private readonly IRegistryReader _registry;
    public FirewallRiskyAllowRulesCheck(IRegistryReader registry) => _registry = registry;

    public CheckMetadata Metadata { get; } = new(
        Id: "HD-FW-03",
        Title: "Có quy tắc firewall cho phép inbound từ bất kỳ địa chỉ nào tới cổng nhạy cảm",
        DefaultSeverity: Severity.High,
        Category: "Tường lửa máy trạm",
        CisReference: "CIS 9.x.4 (Allow rules from any IP)");

    private const string RulesPath =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    /// <summary>
    /// Sensitive listening ports. Key = port, Value = (label, isHighSeverity).
    /// High = lateral movement / pre-auth RCE class (RDP, SMB, WinRM).
    /// Medium = legacy/admin-plane services that should never be exposed without source restriction.
    /// </summary>
    private static readonly Dictionary<int, (string Label, bool IsHigh)> SensitivePorts = new()
    {
        [3389] = ("RDP", true),
        [445]  = ("SMB", true),
        [5985] = ("WinRM-HTTP", true),
        [5986] = ("WinRM-HTTPS", true),
        [135]  = ("RPC Endpoint Mapper", false),
        [139]  = ("NetBIOS-SSN", false),
        [1433] = ("MSSQL", false),
        [3306] = ("MySQL", false),
        [5432] = ("PostgreSQL", false),
        [23]   = ("Telnet", false),
        [21]   = ("FTP", false),
        [22]   = ("SSH", false),
        [5900] = ("VNC", false),
    };

    public Task<Finding?> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var valueNames = _registry.GetValueNames(RegistryHive.LocalMachine, RulesPath);
        if (valueNames.Count == 0)
        {
            return Task.FromResult<Finding?>(null);
        }

        var hits = new List<RiskyRule>();
        var hasHigh = false;

        foreach (var name in valueNames)
        {
            ct.ThrowIfCancellationRequested();
            var raw = _registry.GetValue(RegistryHive.LocalMachine, RulesPath, name) as string;
            if (string.IsNullOrEmpty(raw))
            {
                continue;
            }
            var parsed = ParseRule(raw);
            if (parsed is null)
            {
                continue;
            }
            if (!parsed.IsActive || !parsed.IsAllow || !parsed.IsInbound)
            {
                continue;
            }
            if (!parsed.AllowsAnyRemote)
            {
                continue;
            }
            foreach (var port in parsed.LocalPorts)
            {
                if (!SensitivePorts.TryGetValue(port, out var meta))
                {
                    continue;
                }
                // Skip Windows-shipped rules for RPC/NetBIOS — these are required by
                // domain join, file sharing in workgroup, etc. Only flag if user/attacker
                // ADDED a rule (3rd-party exe). Pattern: AppPath under %SystemRoot%\System32
                // AND EmbedCtxt starts with @FirewallAPI.dll resource handle.
                if ((port is 135 or 139)
                    && IsWindowsShippedRule(parsed.AppPath, parsed.EmbedCtxt))
                {
                    continue;
                }
                if (meta.IsHigh)
                {
                    hasHigh = true;
                }
                hits.Add(new RiskyRule(
                    DisplayName: ResolveDisplayName(parsed.DisplayName, parsed.EmbedCtxt, name),
                    Port: port,
                    PortLabel: meta.Label,
                    Protocol: parsed.ProtocolName,
                    AppPath: parsed.AppPath,
                    ServiceName: parsed.ServiceName,
                    OwnerAccount: ResolveOwner(parsed.LocalUserOwnerSid),
                    Profile: parsed.Profile));
                // Each rule reports once per matching sensitive port; don't break, a rule may
                // open both 5985 AND 5986 in one entry.
            }
        }

        if (hits.Count == 0)
        {
            return Task.FromResult<Finding?>(null);
        }

        var severity = hasHigh ? Severity.High : Severity.Medium;
        var lines = hits
            .OrderBy(h => h.Port)
            .ThenBy(h => h.DisplayName, StringComparer.OrdinalIgnoreCase)
            .Select(FormatRuleLine);
        var evidence = $"{hits.Count} quy tắc Allow inbound từ bất kỳ địa chỉ nào:\n" + string.Join("\n", lines);

        return Task.FromResult<Finding?>(Finding.Create(
            id: Metadata.Id,
            title: Metadata.Title,
            severity: severity,
            category: Metadata.Category,
            asset: ctx.Asset,
            evidence: evidence,
            remediation: "Mở Windows Defender Firewall with Advanced Security → Inbound Rules, "
                         + "tìm các rule liệt kê ở trên, sửa Scope → Remote IP address để hạn chế "
                         + "trong subnet quản trị (vd: 10.0.0.0/8, LocalSubnet) hoặc disable nếu không cần. "
                         + "PowerShell mẫu: "
                         + "Set-NetFirewallRule -DisplayName '<tên rule>' -RemoteAddress LocalSubnet."));
    }

    /// <summary>Pipe-delimited rule parser. Tolerant of unknown tokens — only reads what we need.</summary>
    private static ParsedRule? ParseRule(string raw)
    {
        // Format: v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=...|Name=...|RA4=*|...
        var tokens = raw.Split('|', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length < 2)
        {
            return null;
        }
        var p = new ParsedRule();
        var ports = new List<int>();
        bool sawProtocol = false;
        bool sawAnyRa = false;
        bool foundExplicitRestrictedRa = false;

        foreach (var token in tokens)
        {
            var eq = token.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }
            var key = token.AsSpan(0, eq).Trim();
            var val = token.AsSpan(eq + 1).Trim();

            if (key.Equals("Action", StringComparison.OrdinalIgnoreCase))
            {
                p.IsAllow = val.Equals("Allow", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("Active", StringComparison.OrdinalIgnoreCase))
            {
                p.IsActive = val.Equals("TRUE", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("Dir", StringComparison.OrdinalIgnoreCase))
            {
                p.IsInbound = val.Equals("In", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("Protocol", StringComparison.OrdinalIgnoreCase))
            {
                sawProtocol = true;
                if (int.TryParse(val, NumberStyles.Integer, CultureInfo.InvariantCulture, out var proto))
                {
                    p.ProtocolName = proto switch { 6 => "TCP", 17 => "UDP", 1 => "ICMPv4", 58 => "ICMPv6", _ => proto.ToString(CultureInfo.InvariantCulture) };
                }
            }
            else if (key.Equals("LPort", StringComparison.OrdinalIgnoreCase) ||
                     (key.Length >= 5 && key.StartsWith("LPort", StringComparison.OrdinalIgnoreCase)))
            {
                AddPortsFromToken(val, ports);
            }
            else if (key.Equals("Name", StringComparison.OrdinalIgnoreCase))
            {
                p.DisplayName = val.ToString();
            }
            else if (key.Equals("App", StringComparison.OrdinalIgnoreCase))
            {
                p.AppPath = val.ToString();
            }
            else if (key.Equals("Svc", StringComparison.OrdinalIgnoreCase))
            {
                // Windows service the rule is bound to (e.g. "termservice" for RDP). The
                // SOC operator can map service → owning user via 'sc qc <svc>' if needed.
                p.ServiceName = val.ToString();
            }
            else if (key.Equals("LUOwn", StringComparison.OrdinalIgnoreCase))
            {
                // SDDL-style SID of the principal that authored the rule. Translated to
                // a friendly DOMAIN\user string at render time so the SOC can identify
                // who pushed the exception.
                p.LocalUserOwnerSid = val.ToString();
            }
            else if (key.Equals("EmbedCtxt", StringComparison.OrdinalIgnoreCase))
            {
                // Friendly context string (often the package/owning component's display
                // name) — used as a secondary fallback when Name is an unresolved
                // "@dll,-id" resource reference and we want SOMETHING readable.
                p.EmbedCtxt = val.ToString();
            }
            else if (key.Equals("Profile", StringComparison.OrdinalIgnoreCase))
            {
                p.Profile = val.ToString();
            }
            else if (key.Equals("RA4", StringComparison.OrdinalIgnoreCase) ||
                     key.Equals("RA6", StringComparison.OrdinalIgnoreCase))
            {
                sawAnyRa = true;
                // Wildcard means "any address". Anything else (CIDR, IP range, LocalSubnet token,
                // DNS, etc.) is a real restriction we accept.
                if (!val.Equals("*", StringComparison.Ordinal))
                {
                    foundExplicitRestrictedRa = true;
                }
            }
            else if (key.Equals("RA42", StringComparison.OrdinalIgnoreCase) ||
                     key.Equals("RA62", StringComparison.OrdinalIgnoreCase) ||
                     (key.Length >= 3 && (key.StartsWith("RA4", StringComparison.OrdinalIgnoreCase) ||
                                          key.StartsWith("RA6", StringComparison.OrdinalIgnoreCase))))
            {
                // RA4_*, RA6_* — additional constraint forms (LocalSubnet, named scopes).
                sawAnyRa = true;
                foundExplicitRestrictedRa = true;
            }
        }

        // No remote-address tokens at all => default = any.
        // Only RA*=* present  => any.
        // At least one restricted token => not any.
        p.AllowsAnyRemote = !foundExplicitRestrictedRa;

        if (!sawProtocol)
        {
            p.ProtocolName = "ANY";
        }
        p.LocalPorts = ports;
        // Suppress unused-warning for sawAnyRa — kept for future "rule has zero scoping" trace.
        _ = sawAnyRa;
        return p;
    }

    /// <summary>Token may be a single port "445" or a range "5985-5986" or comma-list "21,22".</summary>
    private static void AddPortsFromToken(ReadOnlySpan<char> val, List<int> sink)
    {
        foreach (var range in val.ToString().Split(','))
        {
            var trimmed = range.Trim();
            var dash = trimmed.IndexOf('-');
            if (dash < 0)
            {
                if (int.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p))
                {
                    sink.Add(p);
                }
                continue;
            }
            if (int.TryParse(trimmed.AsSpan(0, dash), NumberStyles.Integer, CultureInfo.InvariantCulture, out var lo) &&
                int.TryParse(trimmed.AsSpan(dash + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out var hi) &&
                hi >= lo && (hi - lo) <= 64)
            {
                // Cap range expansion at 64 to avoid pathological "0-65535" values blowing memory.
                for (var v = lo; v <= hi; v++)
                {
                    sink.Add(v);
                }
            }
        }
    }

    private sealed class ParsedRule
    {
        public bool IsAllow;
        public bool IsActive;
        public bool IsInbound;
        public bool AllowsAnyRemote;
        public string ProtocolName = "ANY";
        public string? DisplayName;
        public string? EmbedCtxt;
        public string? AppPath;
        public string? ServiceName;
        public string? LocalUserOwnerSid;
        public string? Profile;
        public List<int> LocalPorts = new();
    }

    private sealed record RiskyRule(
        string DisplayName,
        int Port,
        string PortLabel,
        string Protocol,
        string? AppPath,
        string? ServiceName,
        string? OwnerAccount,
        string? Profile);

    /// <summary>
    /// Compose the per-rule line in the evidence block. Each finding now includes the
    /// rule owner (translated SID), the bound Windows service name, the application
    /// path, and the firewall profile — exactly the cluster of attributes the SOC
    /// operator needs to find and explain the rule in MMC.
    /// </summary>
    /// <summary>
    /// True when the firewall rule was shipped by Windows itself (not added by user
    /// or 3rd-party installer). Built-in rules carry an <c>EmbedCtxt</c> token that
    /// references a Windows binary's MUI resource (e.g. <c>@FirewallAPI.dll,-30000</c>);
    /// the rule's AppPath also points at a System32 binary. Flagging these as risky
    /// produces noise — they're required for normal Windows networking and the user
    /// can't simply delete them.
    /// </summary>
    private static bool IsWindowsShippedRule(string? appPath, string? embedCtxt)
    {
        if (!string.IsNullOrEmpty(embedCtxt)
            && embedCtxt[0] == '@'
            && (embedCtxt.Contains("firewallapi.dll", StringComparison.OrdinalIgnoreCase)
                || embedCtxt.Contains("%systemroot%", StringComparison.OrdinalIgnoreCase)
                || embedCtxt.Contains(@"\system32\", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }
        if (string.IsNullOrEmpty(appPath))
        {
            return false;
        }
        var lower = appPath.ToLowerInvariant();
        return lower.Contains(@"\system32\", StringComparison.Ordinal)
            || lower.Contains(@"%systemroot%\system32\", StringComparison.Ordinal)
            || lower.Contains(@"\syswow64\", StringComparison.Ordinal);
    }

    private static string FormatRuleLine(RiskyRule h)
    {
        var sb = new StringBuilder(160);
        sb.Append("  • ").Append(h.Port).Append('/').Append(h.Protocol)
          .Append(" (").Append(h.PortLabel).Append(") — \"").Append(h.DisplayName).Append('"');
        if (!string.IsNullOrEmpty(h.AppPath))
        {
            sb.Append(" → ").Append(h.AppPath);
        }
        if (!string.IsNullOrEmpty(h.ServiceName))
        {
            sb.Append("; service=").Append(h.ServiceName);
        }
        if (!string.IsNullOrEmpty(h.OwnerAccount))
        {
            sb.Append("; người tạo=").Append(h.OwnerAccount);
        }
        if (!string.IsNullOrEmpty(h.Profile))
        {
            sb.Append("; profile=").Append(MapProfile(h.Profile));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Pick the most human-readable label for the rule. Order:
    /// (1) <c>Name</c> if it's a literal string (not a "@dll,-id" resource ref);
    /// (2) <c>Name</c> resolved via SHLoadIndirectString when it IS a resource ref;
    /// (3) <c>EmbedCtxt</c> (friendly context, usually the owning package name);
    /// (4) the registry value name as last resort (a GUID or rule key).
    /// </summary>
    private static string ResolveDisplayName(string? name, string? embedCtxt, string fallback)
    {
        if (!string.IsNullOrEmpty(name))
        {
            if (name.StartsWith('@'))
            {
                var resolved = SafeLoadIndirectString(name);
                if (!string.IsNullOrWhiteSpace(resolved))
                {
                    return resolved!;
                }
                if (!string.IsNullOrWhiteSpace(embedCtxt))
                {
                    var ec = embedCtxt.StartsWith('@') ? SafeLoadIndirectString(embedCtxt) : embedCtxt;
                    if (!string.IsNullOrWhiteSpace(ec))
                    {
                        return ec!;
                    }
                }
                // Fall through to the unresolved "@..." string so the operator can see
                // the source DLL+ID rather than a meaningless GUID.
                return name;
            }
            return name;
        }
        if (!string.IsNullOrEmpty(embedCtxt))
        {
            return embedCtxt;
        }
        return fallback;
    }

    /// <summary>
    /// Translate a SDDL SID string ("S-1-5-21-…") to a friendly "DOMAIN\user" label so
    /// the SOC operator can identify who pushed the firewall exception. Falls back to
    /// the SID itself when translation fails (account deleted, on a domain we can't
    /// reach, etc.) — better than dropping the field entirely.
    /// </summary>
    private static string? ResolveOwner(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return null;
        }
        try
        {
            var s = new SecurityIdentifier(sid);
            var account = (NTAccount)s.Translate(typeof(NTAccount));
            return account.Value;
        }
        catch
        {
            return sid;
        }
    }

    private static string MapProfile(string raw) => raw switch
    {
        "1" => "Domain",
        "2" => "Private",
        "4" => "Public",
        "3" => "Domain+Private",
        "5" => "Domain+Public",
        "6" => "Private+Public",
        "7" => "All",
        _ => raw
    };

    /// <summary>
    /// Resolve an "@dll,-resourceId" reference into the localised friendly string via
    /// <c>SHLoadIndirectString</c>. Returns null on any failure (DLL missing, ID not
    /// in the resource table, etc.) so the caller can apply its own fallback.
    /// Uses a stack-friendly char[] buffer (CA1838: no StringBuilder in P/Invoke).
    /// </summary>
    private static unsafe string? SafeLoadIndirectString(string indirect)
    {
        const int cap = 1024;
        var buf = new char[cap];
        try
        {
            fixed (char* p = buf)
            {
                var hr = SHLoadIndirectString(indirect, p, (uint)cap, IntPtr.Zero);
                if (hr == 0)
                {
                    var len = 0;
                    while (len < cap && buf[len] != '\0') { len++; }
                    if (len == 0) { return null; }
                    var s = new string(buf, 0, len);
                    return string.IsNullOrWhiteSpace(s) ? null : s;
                }
            }
        }
        catch
        {
            // shlwapi may not load on stripped images; fall through.
        }
        return null;
    }

    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern unsafe int SHLoadIndirectString(
        string pszSource,
        char* pszOutBuf,
        uint cchOutBuf,
        IntPtr ppvReserved);
}
