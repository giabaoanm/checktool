using FluentAssertions;
using SecAudit.Cve.Pipeline.Models;
using SecAudit.Modules.PatchCve;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class PatchCoverageEvaluatorTests
{
    [Fact]
    public void Evaluate_covers_rule_by_direct_required_kb()
    {
        var rule = Rule("CVE-2021-34527", "2021-07-06", "KB5004945");
        var installed = new[]
        {
            new InstalledKb("KB5004945", DateTimeOffset.Parse("2021-07-06"), "Security Update", "unit")
        };

        var result = PatchCoverageEvaluator.Evaluate(rule, installed);

        result.IsCovered.Should().BeTrue();
        result.Kind.Should().Be(CoverageKind.DirectKb);
        result.CoveringKb.Should().Be("KB5004945");
    }

    [Fact]
    public void Evaluate_covers_rule_by_later_security_update_supersedence()
    {
        var rule = Rule("CVE-2021-34527", "2021-07-06", "KB5004945");
        var installed = new[]
        {
            new InstalledKb("KB5082200", DateTimeOffset.Parse("2026-04-17"), "Security Update", "unit")
        };

        var result = PatchCoverageEvaluator.Evaluate(rule, installed);

        result.IsCovered.Should().BeTrue();
        result.Kind.Should().Be(CoverageKind.SupersededByLaterSecurityUpdate);
        result.CoveringKb.Should().Be("KB5082200");
    }

    [Fact]
    public void Evaluate_does_not_cover_rule_when_security_update_is_older_than_fix_date()
    {
        var rule = Rule("CVE-2022-30190", "2022-06-14", "KB5014697");
        var installed = new[]
        {
            new InstalledKb("KB5000000", DateTimeOffset.Parse("2021-12-01"), "Security Update", "unit")
        };

        var result = PatchCoverageEvaluator.Evaluate(rule, installed);

        result.IsCovered.Should().BeFalse();
        result.Kind.Should().Be(CoverageKind.None);
    }

    private static FastPathRule Rule(string id, string supersededOnOrAfter, params string[] requiredKbs)
        => new(
            Id: id,
            Title: id,
            Cvss: 8.8,
            Severity: "High",
            RequiredKbAny: requiredKbs,
            AppliesToOsBuildsBelow: 22000,
            AppliesToOsBuildsAbove: null,
            Reference: "https://example.invalid",
            SupersededBySecurityUpdateOnOrAfter: supersededOnOrAfter);
}
