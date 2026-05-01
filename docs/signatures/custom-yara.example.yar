rule SOC_Custom_Suspicious_Launcher_Template
{
    meta:
        verdict = "Suspicious"
        family = "Custom-Launcher-Template"
        confidence = 70
    strings:
        // Replace these placeholder strings with local SOC indicators.
        $a = "unit_loader_name" nocase wide ascii
        $b = "unit_flag_name" nocase wide ascii
        $c = "unit_network_marker" nocase wide ascii
    condition:
        2 of them
}
