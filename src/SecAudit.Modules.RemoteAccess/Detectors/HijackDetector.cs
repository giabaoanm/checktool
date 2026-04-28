using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Infrastructure.Registry;

namespace SecAudit.Modules.RemoteAccess.Detectors;

/// <summary>
/// Detects two classic-but-still-dominant Windows persistence/lockout mechanisms that
/// SecAudit was previously blind to:
///
/// <list type="number">
///   <item>
///     <b>Image File Execution Options (IFEO) Debugger hijack</b> — registry path
///     <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\&lt;exe&gt;</c>.
///     Setting a <c>Debugger</c> value on a binary makes Windows launch the debugger
///     <i>instead</i> of the binary every time the user tries to run it. Malware uses
///     this to hijack <c>explorer.exe</c> (causes the "black screen + cursor only" lock
///     the operator at Sơn La saw), <c>taskmgr.exe</c> (block diagnostics), <c>sethc.exe</c>
///     (sticky-keys backdoor), and similar accessibility binaries.
///   </item>
///   <item>
///     <b>Winlogon hijack</b> — registry path
///     <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</c>. Three values
///     are well-known abuse points:
///     <list type="bullet">
///       <item><c>Shell</c> MUST be exactly <c>explorer.exe</c>. Anything else replaces
///             the user's desktop shell.</item>
///       <item><c>Userinit</c> MUST be exactly <c>C:\Windows\system32\userinit.exe,</c>
///             (note the trailing comma — historical Windows quirk). Malware appends
///             a second binary to chain-load itself at logon.</item>
///       <item><c>Taskman</c> SHOULD be empty. Setting it replaces Task Manager when
///             user presses Ctrl+Alt+Del.</item>
///     </list>
///   </item>
/// </list>
///
/// <para>
/// Detection is purely registry-based — works in both live mode and offline mode where
/// the SOFTWARE hive has been mounted via <c>reg load</c>. No log-channel dependency,
/// so the technique survives an attacker that has cleared the Security log (which is
/// exactly what was observed at Sơn La with 338 cleared-log events).
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HijackDetector
{
    public sealed record HijackHit(
        string Kind,             // "IFEO", "Winlogon-Shell", "Winlogon-Userinit", "Winlogon-Taskman"
        string Target,           // exe name for IFEO; empty for Winlogon
        string ValueName,        // "Debugger", "GlobalFlag", "Shell", "Userinit", "Taskman"
        string ActualValue,
        string ExpectedValue,    // What it SHOULD be — null/empty means "no value"
        string Reason);

    private const string IfeoRoot =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string WinlogonKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    /// <summary>
    /// High-value binaries that attackers target with IFEO Debugger hijack. Any Debugger
    /// value on these is a Critical finding regardless of the value content. Lookup is
    /// case-insensitive (registry sub-key names normalise to lowercase on read).
    /// </summary>
    private static readonly HashSet<string> HighValueIfeoTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        // User-facing shell
        "explorer.exe",
        // Diagnostics / kill-switches the user reaches for when something is wrong
        "taskmgr.exe", "regedit.exe", "msconfig.exe", "cmd.exe", "powershell.exe",
        "powershell_ise.exe", "wmic.exe", "rundll32.exe", "mmc.exe",
        // Accessibility binaries reachable from logon screen → sticky-keys backdoor family
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe",
        // Browsers — IFEO redirect was a popular adware tactic
        "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
        // Security software — disabling the AV via IFEO is a known evasion
        "msmpeng.exe", "mssense.exe", "smartscreen.exe", "securityhealthservice.exe",
        "avp.exe", "avgnt.exe", "avastui.exe", "ekrn.exe",
    };

    private readonly IRegistryReader _registry;
    private readonly ILogger<HijackDetector> _logger;

    public HijackDetector(IRegistryReader registry, ILogger<HijackDetector> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    public IReadOnlyList<HijackHit> Detect()
    {
        var hits = new List<HijackHit>();
        DetectIfeoDebuggerHijack(hits);
        DetectWinlogonHijack(hits);
        return hits;
    }

    /// <summary>
    /// Walk every sub-key under <c>Image File Execution Options</c> and inspect
    /// <c>Debugger</c> / <c>GlobalFlag</c> / <c>VerifierDlls</c> values. Any non-empty
    /// Debugger on a high-value target is Critical; on any other binary it's High (could
    /// be a developer setting, but in a corp workstation context unlikely). GlobalFlag
    /// = <c>0x200</c> (FLG_APPLICATION_VERIFIER) combined with VerifierDlls is a known
    /// stealth-persistence pattern (the loader runs the named DLL inside the target
    /// process — no Debugger value visible at first glance).
    /// </summary>
    private void DetectIfeoDebuggerHijack(List<HijackHit> sink)
    {
        IReadOnlyList<string> targets;
        try
        {
            targets = _registry.GetSubKeyNames(RegistryHive.LocalMachine, IfeoRoot);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cannot enumerate IFEO root");
            return;
        }

        foreach (var exeName in targets)
        {
            var keyPath = $@"{IfeoRoot}\{exeName}";

            string? debugger = null;
            object? globalFlag = null;
            string? verifierDlls = null;
            try
            {
                debugger = _registry.GetValue(RegistryHive.LocalMachine, keyPath, "Debugger") as string;
                globalFlag = _registry.GetValue(RegistryHive.LocalMachine, keyPath, "GlobalFlag");
                verifierDlls = _registry.GetValue(RegistryHive.LocalMachine, keyPath, "VerifierDlls") as string;
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "Cannot read IFEO key {Key}", keyPath);
                continue;
            }

            // Debugger value is the smoking gun. Microsoft never ships these for
            // production binaries — only Visual Studio and devs add them, and never
            // for the targets in HighValueIfeoTargets.
            if (!string.IsNullOrWhiteSpace(debugger))
            {
                bool highValue = HighValueIfeoTargets.Contains(exeName);
                var reason = highValue
                    ? $"Binary '{exeName}' nằm trong danh sách shell/diag/security — Debugger=' {debugger} ' khiến mỗi lần gọi {exeName} chạy debugger thay vì binary gốc. Kỹ thuật này được dùng để khóa explorer.exe (màn hình đen), vô hiệu hóa Task Manager, hoặc cài backdoor sticky-keys."
                    : $"Có Debugger='{debugger}' trên binary {exeName}. IFEO Debugger không bao giờ được Microsoft đặt cho binary production — đây là dấu hiệu hijack.";
                sink.Add(new HijackHit(
                    Kind: "IFEO",
                    Target: exeName,
                    ValueName: "Debugger",
                    ActualValue: debugger!,
                    ExpectedValue: "(không có)",
                    Reason: reason));
            }

            // GlobalFlag 0x200 (FLG_APPLICATION_VERIFIER) + VerifierDlls is the stealth
            // variant — no Debugger value, but loader still injects the named DLL.
            if (!string.IsNullOrWhiteSpace(verifierDlls))
            {
                int gf = globalFlag is int i ? i : 0;
                bool flagSet = (gf & 0x200) != 0;
                sink.Add(new HijackHit(
                    Kind: "IFEO-Verifier",
                    Target: exeName,
                    ValueName: "VerifierDlls",
                    ActualValue: $"VerifierDlls={verifierDlls}; GlobalFlag=0x{gf:X}",
                    ExpectedValue: "(không có)",
                    Reason: flagSet
                        ? $"VerifierDlls đặt trên {exeName} kết hợp GlobalFlag 0x200 — Application Verifier injection: DLL '{verifierDlls}' chạy bên trong tiến trình {exeName} mà không cần debugger value."
                        : $"VerifierDlls='{verifierDlls}' đặt trên {exeName} (chưa kèm GlobalFlag 0x200 nhưng vẫn bất thường ngoài môi trường dev)."));
            }
        }
    }

    /// <summary>
    /// Read the three Winlogon values that must hold canonical defaults on a clean
    /// Windows install. Any deviation = persistence hijack.
    ///
    /// <para>
    /// Canonical values (Win10/11):
    /// <list type="bullet">
    ///   <item><c>Shell</c> = <c>explorer.exe</c> (literal, no path).</item>
    ///   <item><c>Userinit</c> = <c>C:\Windows\system32\userinit.exe,</c> (trailing comma is intentional —
    ///         Userinit's value-list parser uses comma as separator and historically a
    ///         trailing one is required).</item>
    ///   <item><c>Taskman</c> absent or empty.</item>
    /// </list>
    /// </para>
    /// </summary>
    private void DetectWinlogonHijack(List<HijackHit> sink)
    {
        var shell = TryGetString(WinlogonKey, "Shell");
        if (!IsCanonicalShell(shell))
        {
            sink.Add(new HijackHit(
                Kind: "Winlogon-Shell",
                Target: "",
                ValueName: "Shell",
                ActualValue: shell ?? "(không có)",
                ExpectedValue: "explorer.exe",
                Reason: "Winlogon\\Shell phải đúng 'explorer.exe' trên Windows sạch. Bất kỳ giá trị khác đều thay thế shell mặc định khi user đăng nhập — đây là cách malware chiếm desktop."));
        }

        var userinit = TryGetString(WinlogonKey, "Userinit");
        if (!IsCanonicalUserinit(userinit))
        {
            sink.Add(new HijackHit(
                Kind: "Winlogon-Userinit",
                Target: "",
                ValueName: "Userinit",
                ActualValue: userinit ?? "(không có)",
                ExpectedValue: @"C:\Windows\system32\userinit.exe,",
                Reason: "Winlogon\\Userinit phải đúng 'C:\\Windows\\system32\\userinit.exe,' (kèm dấu phẩy cuối). Mọi giá trị thêm vào (vd 'userinit.exe,malware.exe,') sẽ chạy thêm binary lạ ngay khi user đăng nhập."));
        }

        var taskman = TryGetString(WinlogonKey, "Taskman");
        if (!string.IsNullOrWhiteSpace(taskman))
        {
            sink.Add(new HijackHit(
                Kind: "Winlogon-Taskman",
                Target: "",
                ValueName: "Taskman",
                ActualValue: taskman!,
                ExpectedValue: "(không có / rỗng)",
                Reason: "Winlogon\\Taskman ghi đè Task Manager — khi user bấm Ctrl+Alt+Del → Task Manager, Windows chạy binary này thay vì taskmgr.exe."));
        }
    }

    private string? TryGetString(string keyPath, string valueName)
    {
        try
        {
            return _registry.GetValue(RegistryHive.LocalMachine, keyPath, valueName) as string;
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Cannot read {Key}\\{Value}", keyPath, valueName);
            return null;
        }
    }

    /// <summary>
    /// Shell value is canonical when it equals exactly "explorer.exe" (case-insensitive,
    /// trimmed). We DON'T accept a fully-qualified path like "C:\Windows\explorer.exe"
    /// — Windows itself always writes the bare filename, so a path is suspicious even
    /// if the path target IS the legitimate explorer.
    /// </summary>
    internal static bool IsCanonicalShell(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) { return false; }
        return string.Equals(value.Trim(), "explorer.exe", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Userinit canonical form is <c>C:\Windows\system32\userinit.exe,</c>. We accept
    /// case-insensitive match and tolerate forward/backslash mix (rare but seen on some
    /// Windows variants). Anything beyond the trailing comma — even another comma —
    /// indicates a chained payload.
    /// </summary>
    internal static bool IsCanonicalUserinit(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) { return false; }
        var v = value.Trim().Replace('/', '\\');
        // Trailing comma may or may not be present per Microsoft's own writes — accept both.
        if (v.EndsWith(',')) { v = v[..^1]; }
        // Either the simple form "userinit.exe" or the fully-qualified one.
        return string.Equals(v, "userinit.exe", StringComparison.OrdinalIgnoreCase)
            || v.EndsWith(@"\system32\userinit.exe", StringComparison.OrdinalIgnoreCase);
    }
}
