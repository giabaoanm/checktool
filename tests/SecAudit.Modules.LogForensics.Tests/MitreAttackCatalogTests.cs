using FluentAssertions;
using SecAudit.Core.Mitre;
using SecAudit.Core.Models;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Locks down the catalog contract: every constant must round-trip through Lookup,
/// every entry's URL points at attack.mitre.org, and Finding records carry the ids
/// without breaking the existing positional record contract.
/// </summary>
public sealed class MitreAttackCatalogTests
{
    [Fact]
    public void Lookup_round_trips_for_known_id()
    {
        var t = MitreAttackCatalog.Lookup(MitreAttackCatalog.T1003_001);
        t.Should().NotBeNull();
        t!.Id.Should().Be(MitreAttackCatalog.T1003_001);
        t.Name.Should().NotBeNullOrWhiteSpace();
        t.Url.Should().StartWith("https://attack.mitre.org/techniques/");
    }

    [Fact]
    public void Lookup_returns_null_for_unknown_id()
    {
        MitreAttackCatalog.Lookup("T9999.999").Should().BeNull();
    }

    [Fact]
    public void Format_includes_id_for_known_entry()
    {
        MitreAttackCatalog.Format(MitreAttackCatalog.T1547_001)
            .Should().StartWith(MitreAttackCatalog.T1547_001);
    }

    [Fact]
    public void Format_falls_back_to_raw_id_for_unknown()
    {
        MitreAttackCatalog.Format("T9999").Should().Be("T9999");
    }

    [Fact]
    public void Every_constant_resolves_via_Lookup()
    {
        var consts = typeof(MitreAttackCatalog).GetFields(
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetValue(null)!)
            .ToList();

        consts.Should().NotBeEmpty();
        foreach (var id in consts)
        {
            MitreAttackCatalog.Lookup(id).Should().NotBeNull(
                $"constant {id} must have a matching Techniques entry");
        }
    }

    [Fact]
    public void Catalog_has_at_least_30_entries()
    {
        MitreAttackCatalog.Techniques.Count.Should().BeGreaterThanOrEqualTo(30);
    }

    [Fact]
    public void Every_entry_has_non_empty_name_and_well_formed_url()
    {
        foreach (var (id, t) in MitreAttackCatalog.Techniques)
        {
            t.Id.Should().Be(id);
            t.Name.Should().NotBeNullOrWhiteSpace();
            t.Tactic.Should().NotBeNullOrWhiteSpace();
            t.Url.Should().StartWith("https://attack.mitre.org/techniques/");
        }
    }

    [Fact]
    public void Finding_create_defaults_to_empty_attack_techniques()
    {
        var f = Finding.Create(
            id: "X", title: "t", severity: Severity.Low,
            category: "c", asset: "a", evidence: "e", remediation: "r");

        f.AttackTechniqueIds.Should().BeEmpty();
    }

    [Fact]
    public void Finding_create_round_trips_attack_techniques()
    {
        var ids = new[] { MitreAttackCatalog.T1547_001, MitreAttackCatalog.T1210 };
        var f = Finding.Create(
            id: "X", title: "t", severity: Severity.High,
            category: "c", asset: "a", evidence: "e", remediation: "r",
            attackTechniques: ids);

        f.AttackTechniqueIds.Should().Equal(ids);
    }

    [Fact]
    public void Positional_record_contract_unchanged()
    {
        var f = new Finding(
            Id: "X", Title: "t", Severity: Severity.Info,
            CvssScore: null, Category: "c", Asset: "a",
            Evidence: "e", Remediation: "r",
            References: Array.Empty<string>(),
            DetectedAt: DateTimeOffset.UtcNow);

        f.AttackTechniqueIds.Should().BeEmpty();
    }
}
