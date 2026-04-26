using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Infrastructure.OfflineTarget;
using SecAudit.Modules.RemoteAccess.Detectors;
using SecAudit.Modules.SystemInfo;
using SecAudit.Modules.SystemInfo.Models;
using SecAudit.Plugins.Abstractions;

namespace SecAudit.Modules.RemoteAccess;

/// <summary>
/// Iteration 6 — defensive detection of remote-access tooling and persistence beacons
/// based purely on registry / WMI signals. Findings are interpretive guidance for the
/// SOC operator; we never modify or remove anything we detect.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RemoteAccessModule : IAuditModule
{
    /// <summary>
    /// Key for the cross-module <see cref="RemoteAccessSnapshot"/> published so the
    /// formal report's "Phạm vi quét" section can show denominators
    /// (e.g. "5 đáng ngờ / tổng 240 task") instead of just the suspicious count.
    /// </summary>
    public const string SharedSnapshotKey = "remote-access.snapshot";

    private static readonly string[] RefRat =
    {
        "https://attack.mitre.org/techniques/T1219/"
    };
    private static readonly string[] RefRunKeys =
    {
        "https://attack.mitre.org/techniques/T1547/001/"
    };
    private static readonly string[] RefWmiSub =
    {
        "https://attack.mitre.org/techniques/T1546/003/"
    };
    private static readonly string[] RefServices =
    {
        "https://attack.mitre.org/techniques/T1543/003/"
    };
    private static readonly string[] RefScheduledTask =
    {
        "https://attack.mitre.org/techniques/T1053/005/"
    };

    private readonly PersistenceDetector _persistence;
    private readonly WmiPersistenceDetector _wmi;
    private readonly ServicesHiveDetector _services;
    private readonly ScheduledTasksXmlDetector _tasks;
    private readonly IOfflineTarget _target;
    private readonly ILogger<RemoteAccessModule> _logger;

    public RemoteAccessModule(
        PersistenceDetector persistence,
        WmiPersistenceDetector wmi,
        ServicesHiveDetector services,
        ScheduledTasksXmlDetector tasks,
        IOfflineTarget target,
        ILogger<RemoteAccessModule> logger)
    {
        _persistence = persistence;
        _wmi = wmi;
        _services = services;
        _tasks = tasks;
        _target = target;
        _logger = logger;
    }

    public ModuleMetadata Metadata { get; } = new(
        Id: "remote-access",
        DisplayName: "Truy cập từ xa & duy trì truy cập",
        Description: "Phát hiện công cụ điều khiển từ xa đã cài và dấu hiệu duy trì truy cập qua autostart/WMI từ registry.",
        Category: "Bề mặt tấn công",
        Version: "1.0.0",
        RequiresAdministrator: true,
        IsSensitive: false,
        DisplayOrder: 50);

    public Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<object>();
        var asset = context.MachineName;
        int autorunTotal = 0, autorunSuspicious = 0;
        int svcSuspicious = 0, taskSuspicious = 0;
        int? wmiCount = null;

        try
        {
            // 1) Remote-access tools
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang quét phần mềm đã cài để tìm công cụ điều khiển từ xa", 10));
            var inventory = context.GetShared<SystemInventory>(SystemInfoModule.SharedInventoryKey);
            if (inventory is not null)
            {
                var tools = RemoteAccessToolDetector.Detect(inventory.Software);
                foreach (var t in tools)
                {
                    findings.Add(Finding.Create(
                        id: $"RA-TOOL-{Sanitize(t.ProductName)}",
                        title: $"Phát hiện công cụ điều khiển từ xa: {t.ProductName}",
                        severity: ParseSev(t.Severity),
                        category: "Truy cập từ xa",
                        asset: asset,
                        evidence: $"Vendor={t.Vendor}; lý do={t.Why}",
                        remediation: "Xác nhận với người dùng/quản trị xem công cụ này có thực sự cần hay không. Nếu không cần, gỡ qua Settings → Apps. Nếu cần, hạn chế truy cập inbound bằng firewall và bắt buộc MFA trên cổng dịch vụ của nhà cung cấp.",
                        references: RefRat));
                }
            }
            else
            {
                _logger.LogWarning("SystemInfo inventory not available — RAT detection skipped");
                if (!_target.IsLive)
                {
                    findings.Add(Finding.Create(
                        id: "RA-TOOL-OFFLINE",
                        title: "Đã bỏ qua quét phần mềm đã cài (chế độ offline)",
                        severity: Severity.Info,
                        category: "Truy cập từ xa",
                        asset: asset,
                        evidence: "Module SystemInfo bị vô hiệu hóa trong chế độ --offline vì phụ thuộc vào WMI. Nếu cần danh sách phần mềm, có thể liệt kê thủ công key Uninstall tại HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall trên ổ đã mount.",
                        remediation: "Chạy lại ở chế độ live trên chính máy cần kiểm tra sau khi boot an toàn."));
                }
            }

            // 2) Autostart persistence — ONE consolidated row listing every suspicious entry.
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang kiểm tra các mục khởi động Run/RunOnce", 50));
            var autoruns = _persistence.Detect();
            autorunTotal = autoruns.Count;
            var autoSus = autoruns.Where(e => e.Suspicious).ToList();
            autorunSuspicious = autoSus.Count;
            if (autoSus.Count > 0)
            {
                var lines = autoSus.Select(e =>
                    $"• {e.Name} ({e.Hive})\n"
                    + $"    {e.Hive}\\{e.Location}\\{e.Name} = {e.Command}\n"
                    + $"    Lý do: {e.Reason}");
                findings.Add(Finding.Create(
                    id: "RA-RUN",
                    title: $"Có {autoSus.Count} mục khởi động đáng ngờ (tổng {autoruns.Count} mục)",
                    severity: Severity.High,
                    category: "Duy trì truy cập",
                    asset: asset,
                    evidence: string.Join("\n", lines),
                    remediation:
                        "Với mỗi mục: kiểm tra chữ ký và nguồn gốc file (Get-AuthenticodeSignature). Nếu không tin cậy, "
                        + "lưu lại bản sao để điều tra rồi xóa giá trị registry và file gốc.",
                    references: RefRunKeys));
            }

            // 3) Services hive — ONE consolidated row.
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang kiểm tra hive Services để tìm dịch vụ auto-start đáng ngờ", 60));
            var svcHits = _services.Detect();
            svcSuspicious = svcHits.Count;
            if (svcHits.Count > 0)
            {
                var lines = svcHits.Select(svc =>
                    $"• {svc.Name} (Start={svc.Start})\n"
                    + $"    ImagePath={svc.ImagePath}\n"
                    + $"    Lý do: {svc.Reason}");
                findings.Add(Finding.Create(
                    id: "RA-SVC",
                    title: $"Có {svcHits.Count} dịch vụ auto-start đáng ngờ",
                    severity: Severity.High,
                    category: "Duy trì truy cập",
                    asset: asset,
                    evidence: string.Join("\n", lines),
                    remediation:
                        "Với mỗi dịch vụ: 'sc qc <tên>' + Get-AuthenticodeSignature để xác minh nguồn gốc. "
                        + "Nếu không tin cậy: lưu lại file để điều tra rồi 'sc stop <tên> && sc delete <tên>'. "
                        + "Phân tích tiếp binary để tìm dấu hiệu duy trì truy cập khác.",
                    references: RefServices));
            }

            // 4) Scheduled tasks XML — ONE consolidated row.
            progress.Report(new ProgressUpdate(Metadata.Id, "Đang quét định nghĩa XML của scheduled task", 75));
            var taskHits = _tasks.Detect();
            taskSuspicious = taskHits.Count;
            if (taskHits.Count > 0)
            {
                var lines = taskHits.Select(t =>
                    $"• \\Microsoft\\...\\{t.Path}\n"
                    + $"    Command: {Truncate(t.Command, 250)}\n"
                    + $"    Lý do: {t.Reason}");
                findings.Add(Finding.Create(
                    id: "RA-TASK",
                    title: $"Có {taskHits.Count} scheduled task đáng ngờ",
                    severity: Severity.High,
                    category: "Duy trì truy cập",
                    asset: asset,
                    evidence: string.Join("\n", lines),
                    remediation:
                        "Với mỗi task: xuất XML để làm bằng chứng, sau đó 'schtasks /Delete /TN \"<đường dẫn>\" /F' "
                        + "(live) hoặc xóa file XML (offline). Phân tích tiếp binary.",
                    references: RefScheduledTask));
            }

            // 5) WMI permanent event subscriptions — live mode only. ONE consolidated row.
            if (_target.IsLive)
            {
                progress.Report(new ProgressUpdate(Metadata.Id, "Đang truy vấn WMI permanent event subscription", 90));
                var wmiHits = _wmi.Detect();
                wmiCount = wmiHits.Count;
                if (wmiHits.Count > 0)
                {
                    var lines = wmiHits.Select(item =>
                        $"• {item.Class}: {item.Name}\n    {item.Detail}");
                    findings.Add(Finding.Create(
                        id: "RA-WMI",
                        title: $"Có {wmiHits.Count} WMI permanent event subscription đáng ngờ (Windows sạch thường 0–2)",
                        severity: Severity.High,
                        category: "Duy trì truy cập",
                        asset: asset,
                        evidence: string.Join("\n", lines),
                        remediation:
                            "Mọi entry không thuộc Microsoft đều cần điều tra. Liệt kê bằng "
                            + "'Get-WmiObject -Namespace root\\subscription -Class __EventFilter' (tương tự cho ActiveScriptEventConsumer, "
                            + "CommandLineEventConsumer, __FilterToConsumerBinding). Sau khi lưu bằng chứng → 'Remove-WmiObject'.",
                        references: RefWmiSub));
                }
            }
            else
            {
                findings.Add(Finding.Create(
                    id: "RA-WMI-OFFLINE",
                    title: "Đã bỏ qua quét WMI event-subscription (chế độ offline)",
                    severity: Severity.Info,
                    category: "Duy trì truy cập",
                    asset: asset,
                    evidence: "Không thể truy vấn WMI root\\subscription trên ổ đã mount vì repository ở định dạng binary riêng. Cần chạy ở chế độ live trên chính máy để phát hiện lớp duy trì truy cập này (MITRE T1546.003).",
                    remediation: "Khi điều kiện cho phép khởi động bình thường, boot máy lên và chạy lại SecAudit ở chế độ live."));
            }

            // Publish snapshot for the formal report's "Phạm vi quét" section. Done
            // before the success return so it is always available even if some sub-
            // detector hit a partial error.
            context.SetShared(SharedSnapshotKey, new RemoteAccessSnapshot(
                AutorunTotal: autorunTotal,
                AutorunSuspicious: autorunSuspicious,
                ServiceSuspicious: svcSuspicious,
                ScheduledTaskSuspicious: taskSuspicious,
                WmiPersistenceCount: wmiCount));

            progress.Report(new ProgressUpdate(Metadata.Id, "Hoàn tất", 100));
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = true,
                Findings = findings
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RemoteAccessModule failed");
            return Task.FromResult(new ModuleResult
            {
                ModuleId = Metadata.Id,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Succeeded = false,
                FailureReason = ex.Message,
                Findings = findings
            });
        }
    }

    private static Severity ParseSev(string s) => s switch
    {
        "Critical" => Severity.Critical,
        "High" => Severity.High,
        "Medium" => Severity.Medium,
        "Low" => Severity.Low,
        _ => Severity.Info
    };

    private static string Sanitize(string s)
    {
        var chars = s.Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_').ToArray();
        var result = new string(chars);
        return result.Length > 40 ? result[..40] : result;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}

/// <summary>
/// Cross-module snapshot of what RemoteAccessModule actually scanned, regardless
/// of whether anything suspicious was found. Lets the report show denominators
/// like "5 đáng ngờ / tổng 240 task" rather than just the suspicious count.
/// </summary>
public sealed record RemoteAccessSnapshot(
    int AutorunTotal,
    int AutorunSuspicious,
    int ServiceSuspicious,
    int ScheduledTaskSuspicious,
    int? WmiPersistenceCount);
