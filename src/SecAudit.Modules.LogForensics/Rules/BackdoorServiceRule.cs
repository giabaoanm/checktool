using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Windows Event 4697/7045 = "a service was installed". Raises a finding if the service
/// image path hits any suspicious-location indicator, or if the binary name looks random.
/// Good detection for Cobalt-Strike/Metasploit service-install persistence.
/// </summary>
public sealed class BackdoorServiceRule : IDetectionRule
{
    public string Id => "FOR-SVC";
    public string Name => "Cài đặt dịch vụ/backdoor đáng ngờ";

    private static readonly string[] SuspiciousPathMarkers =
    {
        @"\Users\Public\", @"\Windows\Temp\", @"\Temp\", @"\AppData\Local\Temp",
        @"\AppData\Roaming\", @"\ProgramData\", @"\$Recycle.Bin\", @"\PerfLogs\"
    };

    private static readonly string[] SuspiciousCommandMarkers =
    {
        "powershell -e", "powershell.exe -e", "-enc ", "-EncodedCommand",
        "cmd.exe /c ", "wscript.exe", "mshta.exe", "regsvr32.exe /s",
        "rundll32.exe javascript:", "certutil -urlcache", "bitsadmin /transfer"
    };

    private static readonly string[] ReferencesArr =
    {
        "Windows Event ID 7045",
        "MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        var r = record;
        if (r.EventKind != "service.installed") { return; }

        var name = r.GetField("ServiceName") ?? r.GetField("SubjectUserName") ?? "(unknown)";
        var image = r.GetField("ImagePath") ?? r.GetField("ServiceFileName")
            ?? r.GetField("ServiceImagePath") ?? string.Empty;
        var sigLevel = r.GetField("ServiceSignatureStatus");

        var reasons = new List<string>();
        foreach (var m in SuspiciousPathMarkers)
        {
            if (image.Contains(m, StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add($"đường dẫn chứa \"{m.Trim('\\')}\"");
                break;
            }
        }
        foreach (var m in SuspiciousCommandMarkers)
        {
            if (image.Contains(m, StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add($"dùng lệnh nhạy cảm \"{m.Trim()}\"");
                break;
            }
        }
        if (!string.IsNullOrEmpty(sigLevel) && sigLevel.Contains("Unsigned", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("binary không có chữ ký số");
        }
        if (LooksLikeRandomName(name))
        {
            reasons.Add($"tên service ngẫu nhiên \"{name}\"");
        }

        if (reasons.Count == 0) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-{Math.Abs(($"{name}|{image}").GetHashCode()):X8}",
            title: $"Service đáng ngờ được cài đặt: {name}",
            severity: Severity.Critical,
            category: "log-forensics.backdoor",
            asset: $"service:{name}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] ServiceName={name}\n"
                + $"ImagePath={image}\nLý do: {string.Join("; ", reasons)}\n"
                + $"Raw: {r.RawLine}",
            remediation: "Xác minh service này có chính đáng hay không. Nếu không: dừng, gỡ, cách ly máy."
                + " Kiểm tra thêm tiến trình đang chạy, scheduled task và mạng outbound.",
            references: ReferencesArr));
    }

    private static bool LooksLikeRandomName(string name)
    {
        if (name.Length < 8) { return false; }
        int consonants = 0;
        for (int i = 0; i < name.Length - 2; i++)
        {
            var c = char.ToLowerInvariant(name[i]);
            if (!"aeiouy ".Contains(c)) { consonants++; }
            if (consonants >= 6) { return true; }
        }
        return false;
    }

    public void Flush(ForensicsContext ctx) { }
}
