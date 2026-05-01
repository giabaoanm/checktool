rule SOC_Test_Only_SecAudit_Yara_Pack
{
    meta:
        verdict = "TestFile"
        family = "SecAudit-YARA-Pack-Test"
        confidence = 100
    strings:
        $a = "SECAUDIT_YARA_PACK_TEST_ONLY" ascii wide
    condition:
        $a
}

rule SOC_Suspicious_Launcher_Simulation
{
    meta:
        verdict = "Suspicious"
        family = "Internal-Suspicious-Launcher-Simulation"
        confidence = 75
    strings:
        $a = "SECAUDIT_SIMULATED_LOLBIN_LAUNCHER" nocase ascii wide
        $b = "powershell.exe" nocase ascii wide
        $c = "https://internal.example.invalid/payload" nocase ascii wide
    condition:
        2 of them
}

