using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Core.Services;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class FindingTriageInterpreterTests
{
    [Fact]
    public void Interpret_marks_critical_server_attack_as_immediate_high_confidence()
    {
        var finding = Finding.Create(
            "SRV-BRUTE-SUCCESS",
            "Successful logon after many failures from one IP",
            Severity.Critical,
            "server-attack.compromise-suspected",
            "srv01",
            "IpAddress=203.0.113.10; TargetUserName=administrator",
            "Block source IP and review successful logon activity.");

        var triage = FindingTriageInterpreter.Interpret(finding);

        triage.ActionGroup.Should().Be("Cần xử lý ngay");
        triage.Confidence.Should().Be("Cao");
        triage.Scenario.Should().Be("Tấn công trực tuyến");
        triage.Steps.Should().Contain(step => step.Contains("chặn IP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Interpret_marks_hardening_finding_as_policy_based()
    {
        var finding = Finding.Create(
            "HARD-FIREWALL-OFF",
            "Windows Firewall is disabled",
            Severity.High,
            "hardening.firewall",
            "workstation01",
            "Domain profile disabled",
            "Enable Windows Firewall for all profiles.");

        var triage = FindingTriageInterpreter.Interpret(finding);

        triage.ActionGroup.Should().Be("Cần xử lý");
        triage.Confidence.Should().Be("Chính sách");
        triage.Scenario.Should().Be("Cấu hình bảo mật");
        triage.Explanation.Should().Contain("không phải bằng chứng trực tiếp");
    }

    [Fact]
    public void Interpret_marks_network_profile_artifact_as_review()
    {
        var finding = Finding.Create(
            "NET-PROF-WIFI-HISTORY",
            "Network profile history found",
            Severity.Medium,
            "device-forensics.net-prof",
            "workstation01",
            "ProfileName=CorpWiFi; NetworkList registry artifact",
            "Compare with organization network baseline.");

        var triage = FindingTriageInterpreter.Interpret(finding);

        triage.ActionGroup.Should().Be("Cần xem lại");
        triage.Confidence.Should().Be("Chính sách");
        triage.Scenario.Should().Be("Thiết bị / mạng theo chính sách");
        triage.Explanation.Should().Contain("baseline");
    }
}
