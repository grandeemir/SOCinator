/*
    YARA Rule: Ransomware Detection
    Description: Detects ransomware indicators and encryption markers
    MITRE ATT&CK: T1486 (Data Encrypted for Impact)
    Severity: Critical
    False Positives: Legitimate encryption software
*/

rule Ransomware_Indicators {
    meta:
        description = "Detects ransomware encryption indicators"
        mitre_attack_id = "T1486"
        severity = "Critical"
        author = "SOCinator"
        date = "2024-01-01"
    
    strings:
        $s1 = "HOW_TO_DECRYPT"
        $s2 = "YOUR_FILES_ARE_ENCRYPTED"
        $s3 = "DECRYPT_INSTRUCTIONS"
        $s4 = ".encrypted"
        $s5 = ".locked"
        $s6 = "bitcoin"
        $s7 = "ransom"
        
    condition:
        2 of them
}

