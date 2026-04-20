using SecAudit.Core.Models;

namespace SecAudit.Modules.LogForensics.Correlation;

/// <summary>
/// Bộ 8 kill-chain kinh điển được ship sẵn — match thẳng các rule ID hiện có
/// (Security log rules + 10 Sysmon rules mới). Mỗi chain là một
/// <see cref="ICorrelationChain"/> singleton độc lập, đăng ký DI song song.
/// </summary>
public static class PredefinedChains
{
    // --- Static prefix arrays (tái dùng giữa các stage) ---
    private static readonly string[] OfficeChain       = { "SYSMON-OFFICE-CHAIN" };
    private static readonly string[] PsEnc             = { "SYSMON-PSENC" };
    private static readonly string[] LolBinDl          = { "SYSMON-LOLBIN-DL" };
    private static readonly string[] LolBinOrPsEnc     = { "SYSMON-LOLBIN-DL", "SYSMON-PSENC" };
    private static readonly string[] PsEncOrLolBin     = { "SYSMON-PSENC", "SYSMON-LOLBIN-DL" };
    private static readonly string[] LsassOrInject     = { "SYSMON-LSASS", "SYSMON-INJECT" };
    private static readonly string[] DefenderOff       = { "SYSMON-DEFENDER-OFF" };
    private static readonly string[] Ransom            = { "FOR-RANSOM" };
    private static readonly string[] Wipe              = { "FOR-WIPE" };
    private static readonly string[] WmiPersist        = { "SYSMON-WMI" };
    private static readonly string[] ScOrBackdoorSvc   = { "SYSMON-SC-CREATE", "FOR-SVC" };
    private static readonly string[] UnknownOrBrute    = { "FOR-UNKNOWN", "FOR-BRUTE" };
    private static readonly string[] PrivescOrLsass    = { "FOR-PRIVESC", "SYSMON-LSASS" };
    private static readonly string[] SideloadOrInject  = { "SYSMON-SIDELOAD", "SYSMON-INJECT" };
    private static readonly string[] NamedPipe         = { "SYSMON-PIPE" };
    private static readonly string[] LogCleared        = { "FOR-CLEAR" };

    // --- MITRE ATT&CK reference arrays ---
    private static readonly string[] PhishingRefs =
    {
        "MITRE ATT&CK T1566 — Phishing",
        "MITRE ATT&CK T1204 — User Execution",
        "MITRE ATT&CK T1059.001 — PowerShell"
    };
    private static readonly string[] RansomwareRefs =
    {
        "MITRE ATT&CK T1486 — Data Encrypted for Impact",
        "MITRE ATT&CK T1490 — Inhibit System Recovery",
        "MITRE ATT&CK T1562.001 — Impair Defenses"
    };
    private static readonly string[] CredAccessRefs =
    {
        "MITRE ATT&CK T1003.001 — LSASS Memory",
        "MITRE ATT&CK T1055 — Process Injection"
    };
    private static readonly string[] PersistenceRefs =
    {
        "MITRE ATT&CK T1546.003 — WMI Event Subscription",
        "MITRE ATT&CK T1543.003 — Windows Service",
        "MITRE ATT&CK T1547 — Boot or Logon Autostart"
    };
    private static readonly string[] LateralRefs =
    {
        "MITRE ATT&CK T1021 — Remote Services",
        "MITRE ATT&CK T1078 — Valid Accounts"
    };
    private static readonly string[] IngressRefs =
    {
        "MITRE ATT&CK T1105 — Ingress Tool Transfer",
        "MITRE ATT&CK T1059.001 — PowerShell"
    };
    private static readonly string[] DefenseRefs =
    {
        "MITRE ATT&CK T1562.001 — Impair Defenses",
        "MITRE ATT&CK T1070.001 — Clear Windows Event Logs"
    };

    /// <summary>Factory — trả về tất cả chain builtin cho DI.</summary>
    public static IEnumerable<ICorrelationChain> All()
    {
        yield return new SimpleChain(
            id: "CHAIN-PHISH-EXEC",
            name: "Phishing → Execution → Ingress",
            killChain: "Initial Access → Execution → Command & Control",
            stages: new ChainStage[]
            {
                new("Office spawn shell", OfficeChain),
                new("Encoded PowerShell", PsEnc),
                new("LOLBin download payload", LolBinDl)
            },
            window: TimeSpan.FromMinutes(5),
            severity: Severity.Critical,
            references: PhishingRefs);

        yield return new SimpleChain(
            id: "CHAIN-RANSOMWARE",
            name: "Ransomware staging (disable AV → mass encrypt)",
            killChain: "Defense Evasion → Impact",
            stages: new ChainStage[]
            {
                new("Tắt Defender/EDR", DefenderOff),
                new("Ransomware mass-write", Ransom),
                new("Xoá Volume Shadow / anti-recovery", Wipe)
            },
            window: TimeSpan.FromMinutes(10),
            severity: Severity.Critical,
            references: RansomwareRefs);

        yield return new SimpleChain(
            id: "CHAIN-CREDACCESS",
            name: "Credential theft (drop tool → LSASS dump)",
            killChain: "Execution → Credential Access",
            stages: new ChainStage[]
            {
                new("LOLBin download tool", LolBinOrPsEnc),
                new("LSASS access / remote thread", LsassOrInject)
            },
            window: TimeSpan.FromMinutes(10),
            severity: Severity.Critical,
            references: CredAccessRefs);

        yield return new SimpleChain(
            id: "CHAIN-PERSIST-WMI",
            name: "WMI event subscription persistence",
            killChain: "Execution → Persistence",
            stages: new ChainStage[]
            {
                new("Encoded PowerShell / LOLBin", PsEncOrLolBin),
                new("WMI Filter/Consumer/Binding", WmiPersist)
            },
            window: TimeSpan.FromMinutes(10),
            severity: Severity.Critical,
            references: PersistenceRefs);

        yield return new SimpleChain(
            id: "CHAIN-PERSIST-SVC",
            name: "Persistence via new service",
            killChain: "Execution → Persistence",
            stages: new ChainStage[]
            {
                new("Encoded PowerShell / LOLBin", PsEncOrLolBin),
                new("sc create từ user-writable path", ScOrBackdoorSvc)
            },
            window: TimeSpan.FromMinutes(10),
            severity: Severity.Critical,
            references: PersistenceRefs);

        yield return new SimpleChain(
            id: "CHAIN-LATERAL",
            name: "Unknown logon → privilege escalation",
            killChain: "Initial Access → Privilege Escalation",
            stages: new ChainStage[]
            {
                new("Unknown / brute-force logon", UnknownOrBrute),
                new("Privilege escalation signal", PrivescOrLsass)
            },
            window: TimeSpan.FromMinutes(15),
            severity: Severity.Critical,
            references: LateralRefs);

        yield return new SimpleChain(
            id: "CHAIN-INGRESS-C2",
            name: "Ingress tool + named-pipe C2",
            killChain: "Command & Control",
            stages: new ChainStage[]
            {
                new("LOLBin download", LolBinDl),
                new("DLL sideload / injection", SideloadOrInject),
                new("Named-pipe C2 (Cobalt Strike IoC)", NamedPipe)
            },
            window: TimeSpan.FromMinutes(10),
            severity: Severity.Critical,
            references: IngressRefs);

        yield return new SimpleChain(
            id: "CHAIN-DEFEVASION",
            name: "Defense evasion (tắt AV → xoá log)",
            killChain: "Defense Evasion",
            stages: new ChainStage[]
            {
                new("Tắt Defender/EDR", DefenderOff),
                new("Xoá nhật ký Event Log", LogCleared)
            },
            window: TimeSpan.FromMinutes(30),
            severity: Severity.Critical,
            references: DefenseRefs);
    }

    /// <summary>Default DI wrapper quanh các record param.</summary>
    private sealed class SimpleChain : ICorrelationChain
    {
        public string Id { get; }
        public string Name { get; }
        public string KillChain { get; }
        public IReadOnlyList<ChainStage> Stages { get; }
        public TimeSpan Window { get; }
        public Severity FinalSeverity { get; }
        public IReadOnlyList<string> References { get; }

        public SimpleChain(
            string id, string name, string killChain,
            IReadOnlyList<ChainStage> stages, TimeSpan window,
            Severity severity, IReadOnlyList<string> references)
        {
            Id = id;
            Name = name;
            KillChain = killChain;
            Stages = stages;
            Window = window;
            FinalSeverity = severity;
            References = references;
        }
    }
}
