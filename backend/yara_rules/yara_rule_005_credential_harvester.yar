/*
    YARA Rule: Credential Harvester Detection
    Description: Detects credential harvesting and keylogging patterns
    MITRE ATT&CK: T1056 (Input Capture), T1119 (Automated Collection)
    Severity: High
    False Positives: Legitimate password managers, security tools
*/

rule Credential_Harvester {
    meta:
        description = "Detects credential harvesting patterns"
        mitre_attack_id = "T1056, T1119"
        severity = "High"
        author = "SOCinator"
        date = "2024-01-01"
    
    strings:
        $s1 = "password"
        $s2 = "username"
        $s3 = "keylog"
        $s4 = "keystroke"
        $s5 = "GetAsyncKeyState"
        $s6 = "SetWindowsHookEx"
        $s7 = "credential"
        $s8 = "login"
        
    condition:
        ($s1 and $s2) and
        (1 of ($s3, $s4, $s5, $s6)) or
        (($s7 or $s8) and ($s3 or $s4))
}

