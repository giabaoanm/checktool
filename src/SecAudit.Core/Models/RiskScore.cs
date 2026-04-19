namespace SecAudit.Core.Models;

public readonly record struct RiskScore(int Value, string Band)
{
    public static RiskScore FromValue(int v)
    {
        var clamped = Math.Clamp(v, 0, 100);
        var band = clamped switch
        {
            >= 80 => "Excellent",
            >= 60 => "Good",
            >= 40 => "Fair",
            >= 20 => "Poor",
            _ => "Critical"
        };
        return new RiskScore(clamped, band);
    }
}
