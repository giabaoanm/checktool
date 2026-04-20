using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;

namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// MITRE ATT&amp;CK T1574.002 — Hijack Execution Flow: DLL Side-Loading.
///
/// Sysmon Event 7 (ImageLoaded) được ghi mỗi khi một process load DLL. Log đầy
/// ra khủng khiếp nên mặc định Sysmon config hay tắt — nhưng khi bật, nó là
/// signal CỰC mạnh cho DLL sideload.
///
/// <para>
/// Heuristic:
/// 1. Process ký bởi Microsoft (Signed=true, SignatureStatus=Valid) load DLL từ
///    thư mục user-writable (Temp/AppData/ProgramData) — cờ đỏ cổ điển cho
///    sideload qua legitimate binary (plugx, winnti, hikit, ...).
/// 2. DLL không có chữ ký VÀ load bởi process Microsoft trong <c>System32</c> —
///    khả năng DLL search-order hijack.
/// </para>
/// </summary>
public sealed class DllSideloadRule : IDetectionRule
{
    public string Id => "SYSMON-SIDELOAD";
    public string Name => "DLL side-loading qua binary hợp lệ";

    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    /// <summary>
    /// DLL name nổi tiếng bị sideload trong các chiến dịch APT. Nếu thấy 1 trong
    /// các tên này load từ ngoài System32 → phải check ngay.
    /// Nguồn: hijacklibs.net + Mandiant M-Trends.
    /// </summary>
    private static readonly HashSet<string> FrequentlyAbusedDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "wininet.dll", "winhttp.dll", "cryptbase.dll",
        "uxtheme.dll", "msimg32.dll", "dbghelp.dll", "sspicli.dll",
        "secur32.dll", "winsta.dll", "samlib.dll", "rsaenh.dll",
        "oleacc.dll", "textshaping.dll", "textinputframework.dll"
    };

    private static readonly string[] ReferencesArr =
    {
        "Sysmon Event ID 7 — ImageLoaded",
        "MITRE ATT&CK T1574.002 — DLL Side-Loading",
        "hijacklibs.net"
    };

    public void Observe(LogRecord record, ForensicsContext ctx)
    {
        if (record.EventKind != "sysmon.imageload") { return; }

        var image = record.GetField("Image") ?? string.Empty;           // process doing the load
        var imageLoaded = record.GetField("ImageLoaded") ?? string.Empty; // the DLL
        if (string.IsNullOrEmpty(imageLoaded)) { return; }

        var imageSigned = (record.GetField("Signed") ?? string.Empty).Equals("true", StringComparison.OrdinalIgnoreCase);
        var dllSignature = record.GetField("SignatureStatus") ?? string.Empty;
        var imageCompany = record.GetField("Company") ?? string.Empty;
        bool imageIsMicrosoft = imageCompany.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)
            || image.StartsWith(@"C:\Windows\System32\", StringComparison.OrdinalIgnoreCase)
            || image.StartsWith(@"C:\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase);

        bool dllFromUserSpace = SysmonHelpers.IsInUserWritableLocation(imageLoaded);
        bool dllUnsigned = dllSignature.Equals("Unavailable", StringComparison.OrdinalIgnoreCase)
            || dllSignature.Equals("Unsigned", StringComparison.OrdinalIgnoreCase);
        var dllName = SysmonHelpers.GetFileName(imageLoaded);
        bool dllIsKnownAbused = FrequentlyAbusedDlls.Contains(dllName);

        string? reason = null;
        Severity severity = Severity.Medium;

        // Case 1: Microsoft-signed process loading DLL từ user-writable folder → sideload điển hình
        if (imageIsMicrosoft && imageSigned && dllFromUserSpace)
        {
            reason = $"Binary hợp lệ của Microsoft ({SysmonHelpers.GetFileName(image)}) load DLL từ "
                + $"thư mục user-writable ({imageLoaded}) — pattern side-loading điển hình";
            severity = dllIsKnownAbused ? Severity.Critical : Severity.High;
        }
        // Case 2: DLL unsigned có tên nhạy cảm + load bởi Microsoft process
        else if (imageIsMicrosoft && dllUnsigned && dllIsKnownAbused)
        {
            reason = $"DLL không chữ ký {dllName} (trong danh sách hijacklibs) bị load bởi Microsoft binary";
            severity = Severity.High;
        }
        else { return; }

        var key = SysmonHelpers.GetFileName(image) + "|" + imageLoaded.ToLowerInvariant();
        if (!_emitted.Add(key)) { return; }

        ctx.Emit(Finding.Create(
            id: $"{Id}-{SysmonHelpers.StableHash(key)}",
            title: $"Nghi vấn DLL side-load: {SysmonHelpers.GetFileName(image)} ← {dllName}",
            severity: severity,
            category: "log-forensics.execution-hijack",
            asset: $"process:{SysmonHelpers.GetFileName(image)}",
            evidence:
                $"[{record.SourceFile}:{record.SourceOffset}] {record.Timestamp:u}\n"
                + $"Process: {image} (Signed={imageSigned}, Company={imageCompany})\n"
                + $"DLL loaded: {imageLoaded} (SignatureStatus={dllSignature})\n"
                + $"Lý do: {reason}",
            remediation:
                "So hash DLL với bản gốc Microsoft / vendor. Nếu khác: cách ly, submit VT/Defender ATP. "
                + "Kiểm tra EXE cùng thư mục — nhiều khả năng attacker drop một legit EXE + DLL độc cùng "
                + "folder để lợi dụng DLL search order.",
            references: ReferencesArr));
    }

    public void Flush(ForensicsContext ctx) { }
    public void Reset() => _emitted.Clear();
}
