using System.Globalization;
using SecAudit.Cve.Pipeline.Models;

namespace SecAudit.Modules.PatchCve;

public static class PatchCoverageEvaluator
{
    public static PatchCoverageResult Evaluate(
        FastPathRule rule,
        IEnumerable<InstalledKb> installedUpdates)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(installedUpdates);

        var updates = installedUpdates.ToArray();
        var direct = updates.FirstOrDefault(update =>
            rule.RequiredKbAny.Contains(update.KbId, StringComparer.OrdinalIgnoreCase));
        if (direct is not null)
        {
            return PatchCoverageResult.Covered(
                direct.KbId,
                $"đã cài KB vá trực tiếp {direct.KbId}",
                CoverageKind.DirectKb);
        }

        var firstFixedDate = ParseRuleDate(rule.SupersededBySecurityUpdateOnOrAfter);
        if (firstFixedDate is null)
        {
            return PatchCoverageResult.NotCovered("không có KB trực tiếp trong danh sách rule");
        }

        var superseding = updates
            .Where(update => update.InstalledOn is not null)
            .Where(update => update.InstalledOn!.Value.Date >= firstFixedDate.Value.Date)
            .Where(IsWindowsSecurityOrCumulativeUpdate)
            .OrderByDescending(update => update.InstalledOn)
            .ThenByDescending(update => KbNumber(update.KbId))
            .FirstOrDefault();

        if (superseding is not null)
        {
            return PatchCoverageResult.Covered(
                superseding.KbId,
                $"{superseding.KbId} cài ngày {superseding.InstalledOn!.Value:yyyy-MM-dd} là Windows Security/Cumulative Update mới hơn ngày vá đầu tiên {firstFixedDate.Value:yyyy-MM-dd}",
                CoverageKind.SupersededByLaterSecurityUpdate);
        }

        return PatchCoverageResult.NotCovered(
            $"không có KB trực tiếp và không thấy Windows Security/Cumulative Update mới hơn ngày vá đầu tiên {firstFixedDate.Value:yyyy-MM-dd}");
    }

    private static bool IsWindowsSecurityOrCumulativeUpdate(InstalledKb update)
    {
        var description = update.Description ?? string.Empty;
        if (description.Contains("Security Update", StringComparison.OrdinalIgnoreCase)
            || description.Contains("Cumulative Update", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return description.Equals("Update", StringComparison.OrdinalIgnoreCase)
            && KbNumber(update.KbId) >= 5000000;
    }

    private static DateTimeOffset? ParseRuleDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var date))
        {
            return date;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out date)
            ? date
            : null;
    }

    private static int KbNumber(string kb)
        => int.TryParse(
            kb.StartsWith("KB", StringComparison.OrdinalIgnoreCase) ? kb[2..] : kb,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var number)
            ? number
            : 0;
}

public enum CoverageKind
{
    None,
    DirectKb,
    SupersededByLaterSecurityUpdate
}

public sealed record PatchCoverageResult(
    bool IsCovered,
    string? CoveringKb,
    string Reason,
    CoverageKind Kind)
{
    public static PatchCoverageResult Covered(string coveringKb, string reason, CoverageKind kind)
        => new(true, coveringKb, reason, kind);

    public static PatchCoverageResult NotCovered(string reason)
        => new(false, null, reason, CoverageKind.None);
}
