using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules;

/// <summary>
/// Detects keylogger install / persistence signals:
///   * Sysmon Event 13 (Registry Set) writing to the keyboard class UpperFilters key —
///     the canonical kernel-keylogger driver hook.
///   * process.created for a file whose image path matches a known keylogger binary name
///     (case-insensitive string comparison only — we never memory-scan).
///   * bash.command entries that install userland loggers (<c>apt install logkeys</c>, etc.).
/// </summary>
public sealed class KeyloggerRule : IDetectionRule
{
    public string Id => "FOR-KEYLOG";
    public string Name => "Keylogger / driver bàn phím";

    private static readonly string[] KeyboardClassMarkers =
    {
        @"\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}\UpperFilters",
        @"Keyboard Class\UpperFilters"
    };

    // Any non-default value beyond "kbdclass" in UpperFilters is a red flag.
    private static readonly string[] DefaultUpperFilters = { "kbdclass" };

    private static readonly char[] RegValueSeparators = { '\0', '\n', ',', ';', ' ', '\r' };

    private static readonly string[] KeyloggerProcessNames =
    {
        "keylogger", "spyrix", "refog", "ardamax", "actualspy",
        "perfectkeylogger", "klogger", "logkeys", "lkl", "xkeylogger"
    };

    private static readonly string[] InstallCommands =
    {
        "apt install logkeys", "apt-get install logkeys", "pip install pynput",
        "pip3 install pynput", "dnf install logkeys"
    };

    private static readonly string[] ReferencesArr =
    {
        "MITRE ATT&CK T1056.001 — Input Capture: Keylogging",
        "MITRE ATT&CK T1547.003 — Time Providers / driver persistence (related)"
    };

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        switch (record.EventKind)
        {
            case "sysmon.regset":
                HandleRegSet(record, ctx);
                break;
            case "process.created":
            case "sysmon.process":
                HandleProcess(record, ctx);
                break;
            case "bash.command":
                HandleBash(record, ctx);
                break;
        }
    }

    private void HandleRegSet(LogRecord r, ForensicsContext ctx)
    {
        var target = r.GetField("TargetObject") ?? string.Empty;
        var details = r.GetField("Details") ?? string.Empty;
        bool isKbd = false;
        foreach (var m in KeyboardClassMarkers)
        {
            if (target.Contains(m, StringComparison.OrdinalIgnoreCase)) { isKbd = true; break; }
        }
        if (!isKbd) { return; }

        // Flag if ANY value other than the default appears
        var values = details.Split(RegValueSeparators,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var extras = values.Where(v => v.Length > 0
            && !Array.Exists(DefaultUpperFilters, d => d.Equals(v, StringComparison.OrdinalIgnoreCase))).ToList();
        if (extras.Count == 0) { return; }

        var key = "KBD:" + string.Join(",", extras);
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-KBD-{Math.Abs(key.GetHashCode()):X8}",
            title: "Driver bàn phím có UpperFilter lạ — nghi ngờ keylogger kernel",
            severity: Severity.Critical,
            category: "log-forensics.keylogger",
            asset: $"host:{ctx.MachineName}",
            evidence: $"[{r.SourceFile}:{r.SourceOffset}] TargetObject={target}\n"
                + $"Values bất thường: {string.Join(", ", extras)}\nRaw: {r.RawLine}",
            remediation: "Kiểm tra registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-...}\\UpperFilters"
                + " — chỉ được phép có 'kbdclass'. Gỡ các giá trị lạ, reboot, quét AV full.",
            references: ReferencesArr));
    }

    private void HandleProcess(LogRecord r, ForensicsContext ctx)
    {
        var img = r.GetField("Image") ?? r.GetField("NewProcessName") ?? string.Empty;
        var name = Path.GetFileNameWithoutExtension(img).ToLowerInvariant();
        if (string.IsNullOrEmpty(name)) { return; }
        foreach (var kl in KeyloggerProcessNames)
        {
            if (name.Contains(kl, StringComparison.Ordinal))
            {
                var key = "PROC:" + name;
                if (!_emitted.Add(key)) { return; }
                ctx.Emit(Finding.Create(
                    id: $"{Id}-P-{Math.Abs(key.GetHashCode()):X8}",
                    title: $"Tiến trình có tên giống keylogger: {name}",
                    severity: Severity.High,
                    category: "log-forensics.keylogger",
                    asset: $"host:{ctx.MachineName}",
                    evidence: $"[{r.SourceFile}:{r.SourceOffset}] Image={img}\nRaw: {r.RawLine}",
                    remediation: "Xác minh binary (hash + signature). Nếu không hợp lệ: dừng process, cách ly máy, báo SOC.",
                    references: ReferencesArr));
                return;
            }
        }
    }

    private void HandleBash(LogRecord r, ForensicsContext ctx)
    {
        var cmd = r.GetField("Command") ?? string.Empty;
        foreach (var s in InstallCommands)
        {
            if (cmd.Contains(s, StringComparison.OrdinalIgnoreCase))
            {
                var key = "INST:" + s;
                if (!_emitted.Add(key)) { return; }
                ctx.Emit(Finding.Create(
                    id: $"{Id}-I-{Math.Abs(key.GetHashCode()):X8}",
                    title: "Lệnh cài đặt thư viện keylogger",
                    severity: Severity.High,
                    category: "log-forensics.keylogger",
                    asset: $"host:{ctx.MachineName}",
                    evidence: $"[{r.SourceFile}:{r.SourceOffset}] bash history: {cmd}",
                    remediation: "Xác minh tác giả lệnh, kiểm tra các script keylogger có đang chạy (ps auxf).",
                    references: ReferencesArr));
                return;
            }
        }
    }

    public void Flush(ForensicsContext ctx) { }
}
