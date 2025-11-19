# Sigma Rule 008: Suspicious Scheduled Task Creation

## Scenario
This rule detects creation of suspicious scheduled tasks used for persistence and execution. Attackers often use scheduled tasks to maintain access and execute malicious code.

## Log Analysis
The rule searches for:
- `schtasks /create` commands
- Tasks executing `powershell.exe`
- Tasks executing `cmd.exe /c`

## MITRE ATT&CK Mapping
- **Technique ID**: T1053.005
- **Tactic**: Execution, Persistence
- **Technique Name**: Scheduled Task/Job: Scheduled Task

## Severity
**Medium** - Scheduled tasks can be used for persistence and remote code execution.

## False Positive Considerations
- Legitimate automation scripts
- System maintenance tasks
- Backup jobs
- Software installation tasks
- IT operations automation

## Detection Logic
The rule triggers on suspicious scheduled task creation. Monitor:
- Task creation by non-admin users
- Tasks with suspicious command lines
- Tasks running from unusual locations
- Tasks with high privileges
- Tasks connecting to external resources

