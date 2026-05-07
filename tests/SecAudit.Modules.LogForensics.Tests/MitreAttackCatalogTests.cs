using FluentAssertions;
using SecAudit.Core.Mitre;
using SecAudit.Core.Models;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Locks down the ATT&CK mapping contract: every constant on the catalog must have a
/// matching <see cref="MitreAttackCatalog.Techniques"/> entry, the lookup must round-trip
/// via id, and Finding records must accept and round-trip technique ids without breaking
/// the existing positional record contract.
/// </summary>
public sealed class MitreAttackCatalogTests
{
    [Theory]
    [InlineData(MitreAttackCatalog.T1003_001, "OS Credential Dumping")]
    [InlineData(MitreAttackCatalog.T1547_001, "Registry Run Keys")]
    [InlineData(MitreAttackCatalog.T1562_001, "Disable or Modify Tools")]
    [InlineData(MitreAttackCatalog.T1059_001, "PowerShell")]
    [InlineData(MitreAttackCatalog.T1210, "Exploitation of Remote Services")]
    public void Lookup_returns_canonical_name(string id, string expectedNameFragment)
    {
        var t = MitreAttackCatalog.Lookup(id);
        t.Should().NotBeNull();
        t!.Name.Should().Contain(expectedNameFragment);
        t.Url.Should().StartWith("https://attack.mitre.org/techniques/");
    }

    [Fact]
    public void Lookup_returns_null_for_unknown_id()
    {
        MitreAttackCatalog.Lookup("T9999.999").Should().BeNull();
    }

    [Fact]
    public void Format_produces_id_dash_name_for_known_id()
    {
        MitreAttackCatalog.Format(MitreAttackCatalog.T1003_001)
            .Should().Be("T1003.001 — OS Credential Dumping: LSASS Memory");
    }

    [Fact]
    public void Format_falls_back_to_raw_id_for_unknown()
    {
        MitreAttackCatalog.Format("T9999").Should().Be("T9999");
    }

    [Fact]
    public void All_constants_have_a_catalog_entry()
    {
        // Reflective sweep: every public-const string on the catalog must round-trip
        // through Lookup. Catches the common "added a const, forgot the dictionary row" bug.
        var consts = typeof(MitreAttackCatalog).GetFields(
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetValue(null)!)
            .ToList();

        consts.Should().NotBeEmpty();
        foreach (var id in consts)
        {
            MitreAttackCatalog.Lookup(id).Should().NotBeNull(
                $"every catalog constant ({id}) must have a Techniques entry");
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
        var f = Finding.Create(
            id: "X", title: "t", severity: Severity.High,
            category: "c", asset: "a", evidence: "e", remediation: "r",
            attackTechniques: new[] { MitreAttackCatalog.T1003_001, MitreAttackCatalog.T1562_001 });

        f.AttackTechniqueIds.Should().Equal(MitreAttackCatalog.T1003_001, MitreAttackCatalog.T1562_001);
    }

    [Fact]
    public void Positional_record_contract_unchanged()
    {
        // Guards against accidental insertion of AttackTechniqueIds into the positional
        // arg list — that would silently break ~170 Finding.Create call sites.
        var f = new Finding(
            Id: "X",
            Title: "t",
            Severity: Severity.Info,
            CvssScore: null,
            Category: "c",
            Asset: "a",
            Evidence: "e",
            Remediation: "r",
            References: Array.Empty<string>(),
            DetectedAt: DateTimeOffset.UtcNow);

        f.AttackTechniqueIds.Should().BeEmpty();
    }
}
