# Sigma Rule 005: Web Shell Upload Detection

## Scenario
This rule detects potential web shell uploads to web servers. Web shells allow attackers to maintain persistent access and execute commands on compromised web servers.

## Log Analysis
The rule searches for:
- `cmd.php` (common web shell)
- `shell.php` (common web shell)
- `c99.php` (popular PHP web shell)
- `eval(` function (used in web shells)
- `base64_decode` function (obfuscation)
- `system(` function (command execution)

## MITRE ATT&CK Mapping
- **Technique ID**: T1505.003
- **Tactic**: Persistence
- **Technique Name**: Server Software Component: Web Shell

## Severity
**High** - Web shells provide persistent access and can lead to further compromise.

## False Positive Considerations
- Legitimate PHP scripts using eval()
- Development environments
- Content management systems
- Framework code

## Detection Logic
The rule triggers on web shell indicators. Additional monitoring:
- File upload patterns
- Unusual file locations
- Command execution in web logs
- Network connections from web server
- File modification timestamps

