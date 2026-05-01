/*
  SecAudit internal YARA starter pack.

  These rules are intentionally strict and should be copied into signatures\yara only
  after your SOC validates them against confirmed internal samples and clean baselines.
  The SecAudit lightweight YARA engine supports text/hex strings, nocase, wide ascii,
  any/all/N of them, and simple $a and $b style conditions.
*/

rule SOC_Verified_EncodedPowerShell_Download_Persistence
{
    meta:
        verdict = "Suspicious"
        family = "EncodedPowerShell-Downloader-Persistence"
        confidence = 82
    strings:
        $a = "powershell" nocase wide ascii
        $b = "encodedcommand" nocase wide ascii
        $c = "frombase64string" nocase wide ascii
        $d = "downloadstring" nocase wide ascii
        $e = "invoke-webrequest" nocase wide ascii
        $f = "schtasks /create" nocase wide ascii
        $g = "\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $h = "\\AppData\\" nocase wide ascii
    condition:
        4 of them
}

rule SOC_Verified_LNK_LOLBin_Remote_UserWritable
{
    meta:
        verdict = "Suspicious"
        family = "Shortcut-Remote-LOLBin-UserWritable"
        confidence = 80
    strings:
        $a = "powershell.exe" nocase wide ascii
        $b = "mshta.exe" nocase wide ascii
        $c = "regsvr32.exe" nocase wide ascii
        $d = "rundll32.exe" nocase wide ascii
        $e = "http://" nocase wide ascii
        $f = "https://" nocase wide ascii
        $g = "\\AppData\\" nocase wide ascii
        $h = "%TEMP%" nocase wide ascii
        $i = "-windowstyle hidden" nocase wide ascii
    condition:
        4 of them
}

rule SOC_Verified_Ransomware_Tamper_Commands
{
    meta:
        verdict = "Malicious"
        family = "Ransomware-Tamper-Command-Set"
        confidence = 90
    strings:
        $a = "vssadmin delete shadows" nocase wide ascii
        $b = "wmic shadowcopy delete" nocase wide ascii
        $c = "bcdedit" nocase wide ascii
        $d = "recoveryenabled no" nocase wide ascii
        $e = "wbadmin delete catalog" nocase wide ascii
        $f = "DisableRealtimeMonitoring" nocase wide ascii
        $g = "Set-MpPreference" nocase wide ascii
    condition:
        2 of them
}
