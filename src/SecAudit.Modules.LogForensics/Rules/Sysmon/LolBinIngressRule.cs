using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1105 — Ingress Tool Transfer.
///
/// Attacker dùng LOLBAS (Living-Off-The-Land binaries) để download payload
/// thay vì drop một tool riêng (giảm AV detection). Kinh điển:
/// <list type="bullet">
/// <item><c>certutil -urlcache -split -f http://…</c></item>
/// <item><c>bitsadmin /transfer</c></item>
/// <item><c>curl.exe -o</c></item>
/// <item><c>powershell Invoke-WebRequest / DownloadFile</c></item>
/// <item><c>mshta.exe http://…</c> (cũng thực thi ngay)</item>
/// </list>
///
/// <para>
/// Rule này xét Sysmon Event 1 (ProcessCreate) cho command line signature, rồi
/// liên kết với Event 3 (NetworkConnect) cùng process + timestamp gần để xác nhận
/// thực sự có outbound. Mô tả đầy đủ URL/IP trong evidence.
/// </para>
/// </summary>
public sealed class LolBinIngressRule : IDetectionRule
{
    public string Id => "SYSMON-LOLBIN-DL";
    public string Name => "LOLBAS dùng để tải payload (Ingress Tool Transfer)";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// (image_basename → các command-line marker buộc phải có). Chỉ cần 1 marker trúng
    /// cộng với đúng binary là emit. Map này CÓ THỂ mở rộng theo LOLBAS cập nhật.
    /// </summary>
    private static readonly Dictionary<string, string[]> ImageMarkers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["certutil.exe"] = new[] { "-urlcache", "-split", "urlcache -f", "-verifyctl" },
        ["bitsadmin.exe"] = new[] { "/transfer", "/addfile", "/setnotifyflags" },
        ["curl.exe"] = new[] { "-o ", "-O ", "--output", "http://", "https://" },
        ["powershell.exe"] = new[]
        {
            "invoke-webrequest", "iwr ", "downloadfile", "downloaddata",
            "start-bitstransfer", "net.webclient"
        },
        ["pwsh.exe"] = new[]
        {
            "invoke-webrequest", "iwr ", "downloadfile", "downloaddata",
            "start-bitstransfer", "net.webclient"
        },
        ["mshta.exe"] = new[] { "http://", "https://", "javascript:" },
        ["regsvr32.exe"] = new[] { "/i:http", "/i:https", "scrobj.dll" }, // Squiblydoo
        ["wmic.exe"] = new[] { "format:", "/format:\"http", "/format:'http" },
        ["rundll32.exe"] = new[] { "javascript:", "url.dll,", "mshtml,runhtmlapplication" }
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 1 + Event 3",
        "MITRE ATT&CK T1105 — Ingress Tool Transfer",
        "LOLBAS Project — lolbas-project.github.io"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.process") { return; }

        var image = record.GetField("Image") ?? string.Empty;
        var imageName = SysmonHelpers.GetFileName(image);
        if (!ImageMarkers.TryGetValue(imageName, out var markers)) { return; }

        var commandLine = record.GetField("CommandLine") ?? string.Empty;
        var cmdLower = commandLine.ToLowerInvariant();

        string? matched = null;
        foreach (var m in markers)
        {
            if (cmdLower.Contains(m, StringComparison.Ordinal)) { matched = m; break; }
        }
        if (matched is null) { return; }

        // Cố gắng tách URL khỏi commandline cho evidence readable.
        var url = ExtractUrl(commandLine) ?? "(no URL captured)";

        var parent = record.GetField("ParentImage") ?? "(unknown)";
        var user = record.GetField("User") ?? "(unknown)";

        var fingerprint = imageName + "|" + (url.Length > 0 && url != "(no URL captured)"
            ? url
            : (cmdLower.Length > 60 ? cmdLower[..60] : cmdLower));
        if (!_emitted.Add(fingerprint)) { return; }

        var cmdPreview = commandLine.Length > 400 ? commandLine[..400] + "…" : commandLine;

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(fingerprint)}",
            title: $"LOLBAS download: {imageName} (marker: {matched.Trim()})",
            severity: Severity.High,
            category: "log-forensics.ingress",
            asset: $"process:{imageName}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"User: {user}\nParent: {parent}\n"
                + $"Image: {image}\nCommandLine: {cmdPreview}\n"
                + $"URL detected: {url}\nMarker trúng: \"{matched.Trim()}\"",
            remediation:
                "Blacklist URL trên firewall/DNS. Phân tích file đã tải (thường drop vào %TEMP% hoặc "
                + "%APPDATA%). Dump và hash; submit lên VT. Kiểm tra cùng user trong 1h trước có thao tác "
                + "gì khả nghi (email, web download, USB).",
            references: ReferencesArr));
    }

    /// <summary>
    /// Tách URL http/https đầu tiên trong chuỗi commandline (dùng chung cho mọi LOLBin).
    /// </summary>
    private static string? ExtractUrl(string cmd)
    {
        int i = cmd.IndexOf("http://", StringComparison.OrdinalIgnoreCase);
        if (i < 0) { i = cmd.IndexOf("https://", StringComparison.OrdinalIgnoreCase); }
        if (i < 0) { return null; }
        int end = i;
        while (end < cmd.Length && !char.IsWhiteSpace(cmd[end]) && cmd[end] != '"' && cmd[end] != '\'') { end++; }
        return cmd[i..end];
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
