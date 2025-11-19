# Sigma Rule 002: Lateral Movement via WMI

## Scenario
This rule detects lateral movement attempts using Windows Management Instrumentation (WMI). Attackers use WMI to execute commands on remote systems, move laterally across networks, and maintain persistence.

## Log Analysis
The rule searches for:
- `wmic.exe` execution
- `wmic process call create` commands
- `Win32_Process` WMI class usage

## MITRE ATT&CK Mapping
- **Technique ID**: T1047
- **Tactic**: Execution
- **Technique Name**: Windows Management Instrumentation

## Severity
**High** - WMI abuse is a common technique for lateral movement and remote code execution.

## False Positive Considerations
- Legitimate system administration tasks
- Remote management tools (SCCM, etc.)
- Automated deployment systems
- IT operations scripts

## Detection Logic
The rule triggers on WMI-related commands. Consider adding context:
- Remote system connections
- Unusual user accounts
- Off-hours execution
- Network connections to multiple systems

