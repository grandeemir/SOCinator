# Sigma Rule 004: Ransomware Indicators

## Scenario
This rule detects common ransomware behavior patterns, including file encryption markers and ransom notes. Ransomware is a critical threat that can cause significant business disruption.

## Log Analysis
The rule searches for:
- `.encrypted` file extensions
- `.locked` file extensions
- `.crypto` file extensions
- `HOW_TO_DECRYPT` text (common ransom note)
- `README_TO_DECRYPT` text (common ransom note)

## MITRE ATT&CK Mapping
- **Technique ID**: T1486
- **Tactic**: Impact
- **Technique Name**: Data Encrypted for Impact

## Severity
**Critical** - Ransomware can encrypt entire systems and cause business disruption.

## False Positive Considerations
- Legitimate encryption software
- Backup and archiving tools
- File compression utilities
- Development environments with test files

## Detection Logic
The rule triggers on ransomware indicators. Consider monitoring:
- Rapid file system changes
- Encryption process activity
- Network connections to C2 servers
- Ransom note file creation
- Volume shadow copy deletion

