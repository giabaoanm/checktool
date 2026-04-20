using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;

namespace SecAudit.Modules.LogForensics.Correlation;

/// <summary>
/// Multi-step correlation chain — ghép nhiều <see cref="Finding"/> đã được các
/// <see cref="IDetectionRule"/> emit thành một kịch bản tấn công theo MITRE
/// ATT&amp;CK kill chain. Mỗi chain định nghĩa thứ tự (hoặc tập hợp) các
/// <c>rule id</c> phải xảy ra, cùng pivot key (user / host / process), trong
/// một cửa sổ thời gian giới hạn.
///
/// Khi matched đầy đủ chain, engine phát ra một Finding Critical "kill-chain"
/// tóm lược toàn bộ các bước — analyst chỉ cần nhìn 1 dòng là hiểu toàn bộ
/// intrusion, thay vì 5 finding rời rạc.
/// </summary>
public interface ICorrelationChain
{
    /// <summary>Stable ID (ví dụ "CHAIN-PHISH-EXEC") — prefix của Finding.Id khi match.</summary>
    string Id { get; }

    /// <summary>Tên tiếng Việt cho analyst/báo cáo.</summary>
    string Name { get; }

    /// <summary>Mô tả kill-chain stage (Initial Access → Execution → ...).</summary>
    string KillChain { get; }

    /// <summary>
    /// Chain stages — phải khớp theo thứ tự trong cửa sổ <see cref="Window"/>.
    /// Mỗi stage chứa các prefix rule-id được chấp nhận (OR-match) cộng condition tuỳ chọn.
    /// </summary>
    IReadOnlyList<ChainStage> Stages { get; }

    /// <summary>Cửa sổ thời gian tối đa giữa stage đầu và stage cuối.</summary>
    TimeSpan Window { get; }

    /// <summary>Severity cho finding tổng — thường Critical vì chain đã khẳng định ít false-positive.</summary>
    Severity FinalSeverity { get; }

    /// <summary>MITRE ATT&amp;CK references để nhét vào Finding.References.</summary>
    IReadOnlyList<string> References { get; }
}

/// <summary>
/// Một bước trong chain. Chấp nhận nhiều rule-id prefix (OR) — ví dụ
/// "SYSMON-LSASS" OR "SYSMON-INJECT" đều tính là stage CredentialAccess.
/// </summary>
public sealed record ChainStage(
    string Label,
    IReadOnlyList<string> AcceptedRuleIdPrefixes);
