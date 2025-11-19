# YARA Rule 002: Ransomware Detection

## Scenario
This rule detects ransomware indicators and encryption markers in files. Ransomware encrypts files and demands payment for decryption.

## File Analysis
The rule searches for:
- `HOW_TO_DECRYPT` text
- `YOUR_FILES_ARE_ENCRYPTED` text
- `DECRYPT_INSTRUCTIONS` text
- `.encrypted` file extension references
- `.locked` file extension references
- `bitcoin` references (common payment method)
- `ransom` keyword

## MITRE ATT&CK Mapping
- **Technique ID**: T1486
- **Tactic**: Impact
- **Technique Name**: Data Encrypted for Impact

## Severity
**Critical** - Ransomware can encrypt entire systems and cause business disruption.

## False Positive Considerations
- Legitimate encryption software documentation
- Security research files
- Educational materials about ransomware
- Backup software with encryption features

## Detection Logic
The rule triggers when 2 or more indicators are found:
- Ransom notes or instructions
- File extension markers
- Payment method references
- Ransom-related keywords

## Usage Notes
This rule is highly effective at detecting ransomware. However, legitimate encryption tools may trigger false positives. Context is important for accurate detection.

