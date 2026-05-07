// CA1707 — underscores mirror the dot in ATT&CK sub-technique ids (T1003.001 → T1003_001).
// Removing them would erase the semantic boundary between technique and sub-technique.
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Naming", "CA1707:Identifiers should not contain underscores",
    Scope = "type", Target = "~T:SecAudit.Core.Mitre.MitreAttackCatalog",
    Justification = "Underscore models the dot in ATT&CK sub-technique ids.")]

namespace SecAudit.Core.Mitre;

/// <summary>
/// Static lookup for the MITRE ATT&amp;CK technique IDs that SecAudit findings
/// reference. Keeps the canonical display names + URLs in one place so report
/// writers don't drift from the IDs encoded on each finding.
///
/// <para>Source: ATT&amp;CK Enterprise v15 (April 2024).
/// Only techniques actually emitted by SecAudit modules are listed — adding an
/// ID here without a corresponding finding emitter is a smell.</para>
///
/// <para>To add a new technique:</para>
/// <list type="number">
///   <item>Add an entry to <see cref="Techniques"/> with the canonical name from
///         attack.mitre.org.</item>
///   <item>Reference the constant from the relevant check/detector via
///         <c>Finding.Create(..., attackTechniques: new[] { Mitre.T1003_001 })</c>.</item>
///   <item>If a sub-technique (e.g. <c>T1547.001</c>) is added, ensure the parent
///         (<c>T1547</c>) is also present so reports can render hierarchies.</item>
/// </list>
/// </summary>
public static class MitreAttackCatalog
{
    // Constants — short string-literal aliases so call sites stay readable:
    //   Finding.Create(..., attackTechniques: new[] { MitreAttackCatalog.T1003_001 })
    public const string T1003 = "T1003";
    public const string T1003_001 = "T1003.001";
    public const string T1027 = "T1027";
    public const string T1046 = "T1046";
    public const string T1053 = "T1053";
    public const string T1053_005 = "T1053.005";
    public const string T1059 = "T1059";
    public const string T1059_001 = "T1059.001";
    public const string T1068 = "T1068";
    public const string T1078 = "T1078";
    public const string T1105 = "T1105";
    public const string T1110 = "T1110";
    public const string T1112 = "T1112";
    public const string T1136_001 = "T1136.001";
    public const string T1190 = "T1190";
    public const string T1210 = "T1210";
    public const string T1218 = "T1218";
    public const string T1219 = "T1219";
    public const string T1543_003 = "T1543.003";
    public const string T1546_003 = "T1546.003";
    public const string T1546_012 = "T1546.012";
    public const string T1547 = "T1547";
    public const string T1547_001 = "T1547.001";
    public const string T1547_004 = "T1547.004";
    public const string T1553_002 = "T1553.002";
    public const string T1555 = "T1555";
    public const string T1562_001 = "T1562.001";
    public const string T1562_002 = "T1562.002";
    public const string T1562_004 = "T1562.004";
    public const string T1564 = "T1564";
    public const string T1566 = "T1566";
    public const string T1570 = "T1570";
    public const string T1588_001 = "T1588.001";

    public sealed record Technique(string Id, string Name, string Tactic, string Url);

    /// <summary>Canonical map from technique id → display metadata.</summary>
    public static IReadOnlyDictionary<string, Technique> Techniques { get; } =
        new Dictionary<string, Technique>(StringComparer.Ordinal)
        {
            [T1003] = new(T1003, "OS Credential Dumping", "Credential Access", "https://attack.mitre.org/techniques/T1003/"),
            [T1003_001] = new(T1003_001, "OS Credential Dumping: LSASS Memory", "Credential Access", "https://attack.mitre.org/techniques/T1003/001/"),
            [T1027] = new(T1027, "Obfuscated Files or Information", "Defense Evasion", "https://attack.mitre.org/techniques/T1027/"),
            [T1046] = new(T1046, "Network Service Discovery", "Discovery", "https://attack.mitre.org/techniques/T1046/"),
            [T1053] = new(T1053, "Scheduled Task/Job", "Execution / Persistence", "https://attack.mitre.org/techniques/T1053/"),
            [T1053_005] = new(T1053_005, "Scheduled Task/Job: Scheduled Task", "Persistence", "https://attack.mitre.org/techniques/T1053/005/"),
            [T1059] = new(T1059, "Command and Scripting Interpreter", "Execution", "https://attack.mitre.org/techniques/T1059/"),
            [T1059_001] = new(T1059_001, "PowerShell", "Execution", "https://attack.mitre.org/techniques/T1059/001/"),
            [T1068] = new(T1068, "Exploitation for Privilege Escalation", "Privilege Escalation", "https://attack.mitre.org/techniques/T1068/"),
            [T1078] = new(T1078, "Valid Accounts", "Initial Access / Persistence", "https://attack.mitre.org/techniques/T1078/"),
            [T1105] = new(T1105, "Ingress Tool Transfer", "Command and Control", "https://attack.mitre.org/techniques/T1105/"),
            [T1110] = new(T1110, "Brute Force", "Credential Access", "https://attack.mitre.org/techniques/T1110/"),
            [T1112] = new(T1112, "Modify Registry", "Defense Evasion", "https://attack.mitre.org/techniques/T1112/"),
            [T1136_001] = new(T1136_001, "Create Account: Local Account", "Persistence", "https://attack.mitre.org/techniques/T1136/001/"),
            [T1190] = new(T1190, "Exploit Public-Facing Application", "Initial Access", "https://attack.mitre.org/techniques/T1190/"),
            [T1210] = new(T1210, "Exploitation of Remote Services", "Lateral Movement", "https://attack.mitre.org/techniques/T1210/"),
            [T1218] = new(T1218, "System Binary Proxy Execution", "Defense Evasion", "https://attack.mitre.org/techniques/T1218/"),
            [T1219] = new(T1219, "Remote Access Software", "Command and Control", "https://attack.mitre.org/techniques/T1219/"),
            [T1543_003] = new(T1543_003, "Create or Modify System Process: Windows Service", "Persistence", "https://attack.mitre.org/techniques/T1543/003/"),
            [T1546_003] = new(T1546_003, "Event Triggered Execution: WMI Event Subscription", "Persistence", "https://attack.mitre.org/techniques/T1546/003/"),
            [T1546_012] = new(T1546_012, "Event Triggered Execution: Image File Execution Options Injection", "Persistence", "https://attack.mitre.org/techniques/T1546/012/"),
            [T1547] = new(T1547, "Boot or Logon Autostart Execution", "Persistence", "https://attack.mitre.org/techniques/T1547/"),
            [T1547_001] = new(T1547_001, "Registry Run Keys / Startup Folder", "Persistence", "https://attack.mitre.org/techniques/T1547/001/"),
            [T1547_004] = new(T1547_004, "Winlogon Helper DLL", "Persistence", "https://attack.mitre.org/techniques/T1547/004/"),
            [T1553_002] = new(T1553_002, "Subvert Trust Controls: Code Signing", "Defense Evasion", "https://attack.mitre.org/techniques/T1553/002/"),
            [T1555] = new(T1555, "Credentials from Password Stores", "Credential Access", "https://attack.mitre.org/techniques/T1555/"),
            [T1562_001] = new(T1562_001, "Impair Defenses: Disable or Modify Tools", "Defense Evasion", "https://attack.mitre.org/techniques/T1562/001/"),
            [T1562_002] = new(T1562_002, "Impair Defenses: Disable Windows Event Logging", "Defense Evasion", "https://attack.mitre.org/techniques/T1562/002/"),
            [T1562_004] = new(T1562_004, "Impair Defenses: Disable or Modify System Firewall", "Defense Evasion", "https://attack.mitre.org/techniques/T1562/004/"),
            [T1564] = new(T1564, "Hide Artifacts", "Defense Evasion", "https://attack.mitre.org/techniques/T1564/"),
            [T1566] = new(T1566, "Phishing", "Initial Access", "https://attack.mitre.org/techniques/T1566/"),
            [T1570] = new(T1570, "Lateral Tool Transfer", "Lateral Movement", "https://attack.mitre.org/techniques/T1570/"),
            [T1588_001] = new(T1588_001, "Obtain Capabilities: Malware", "Resource Development", "https://attack.mitre.org/techniques/T1588/001/"),
        };

    /// <summary>Returns the technique metadata, or <c>null</c> if id is unknown.</summary>
    public static Technique? Lookup(string id)
        => Techniques.TryGetValue(id, out var t) ? t : null;

    /// <summary>Builds a "T1003.001 — OS Credential Dumping: LSASS Memory" string,
    /// or just the raw id when unknown. Safe to call with arbitrary input.</summary>
    public static string Format(string id)
        => Lookup(id) is { } t ? $"{t.Id} — {t.Name}" : id;
}
