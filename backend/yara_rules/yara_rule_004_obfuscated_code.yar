/*
    YARA Rule: Obfuscated Code Detection
    Description: Detects obfuscated and encoded malicious code
    MITRE ATT&CK: T1027 (Obfuscated Files or Information)
    Severity: Medium
    False Positives: Legitimate obfuscated software, minified code
*/

rule Obfuscated_Code {
    meta:
        description = "Detects obfuscated malicious code patterns"
        mitre_attack_id = "T1027"
        severity = "Medium"
        author = "SOCinator"
        date = "2024-01-01"
    
    strings:
        $s1 = /[A-Za-z0-9+\/]{100,}/ // Base64 encoded content
        $s2 = "eval("
        $s3 = "unescape("
        $s4 = "fromCharCode"
        $s5 = "String.fromCharCode"
        $s6 = /\\x[0-9a-f]{2}/ // Hex encoding
        
    condition:
        ($s1 and $s2) or
        ($s2 and ($s3 or $s4 or $s5)) or
        (3 of ($s6))
}

