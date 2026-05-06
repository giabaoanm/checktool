namespace SecAudit.Core.Models;

/// <summary>
/// Operator-facing interpretation for a raw finding. It does not change the
/// detection result; it explains how a human should triage and handle it.
/// </summary>
public sealed record FindingTriage(
    string ActionGroup,
    string Confidence,
    string Scenario,
    string Explanation,
    IReadOnlyList<string> Steps)
{
    public string StepsText
    {
        get
        {
            if (Steps.Count == 0)
            {
                return string.Empty;
            }

            return string.Join(
                Environment.NewLine,
                Steps.Select((step, index) => $"{index + 1}. {step}"));
        }
    }
}
