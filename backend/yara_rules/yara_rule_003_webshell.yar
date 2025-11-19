/*
    YARA Rule: Web Shell Detection
    Description: Detects common web shell patterns in files
    MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)
    Severity: High
    False Positives: Legitimate PHP/ASP scripts with similar patterns
*/

rule WebShell_Detection {
    meta:
        description = "Detects web shell code patterns"
        mitre_attack_id = "T1505.003"
        severity = "High"
        author = "SOCinator"
        date = "2024-01-01"
    
    strings:
        $php1 = "<?php"
        $php2 = "eval("
        $php3 = "base64_decode"
        $php4 = "system("
        $php5 = "exec("
        $php6 = "shell_exec"
        $php7 = "passthru"
        $asp1 = "<%"
        $asp2 = "eval"
        $asp3 = "execute"
        
    condition:
        ($php1 and 2 of ($php2, $php3, $php4, $php5, $php6, $php7)) or
        ($asp1 and 2 of ($asp2, $asp3))
}

