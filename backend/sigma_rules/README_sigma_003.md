# Sigma Rule 003: Credential Dumping Activity

## Scenario
This rule detects attempts to dump credentials from memory or registry. Credential dumping is a critical attack technique used to extract passwords, hashes, and other authentication materials.

## Log Analysis
The rule searches for:
- `mimikatz` references (popular credential dumping tool)
- `lsass.exe` access (Local Security Authority Subsystem Service)
- `sekurlsa::` commands (Mimikatz module)
- Registry saves of SAM and SYSTEM hives

## MITRE ATT&CK Mapping
- **Technique ID**: T1003
- **Tactic**: Credential Access
- **Technique Name**: OS Credential Dumping

## Severity
**Critical** - Credential dumping can lead to complete system compromise and lateral movement.

## False Positive Considerations
- Legitimate backup operations
- Security tools performing forensic analysis
- System recovery procedures
- Authorized security assessments

## Detection Logic
The rule triggers on credential dumping indicators. Additional context to consider:
- Process access to lsass.exe
- Unusual registry operations
- Memory access patterns
- Security tool whitelisting

