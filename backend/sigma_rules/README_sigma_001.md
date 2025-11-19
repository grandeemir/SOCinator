# Sigma Rule 001: Suspicious PowerShell Execution

## Scenario
This rule detects suspicious PowerShell execution patterns commonly used in cyber attacks. Attackers often use PowerShell to execute malicious scripts, download payloads, and perform various attack activities.

## Log Analysis
The rule searches for:
- `powershell.exe` execution
- `powershell_ise.exe` execution  
- `pwsh.exe` (PowerShell Core) execution

## MITRE ATT&CK Mapping
- **Technique ID**: T1059.001
- **Tactic**: Execution
- **Technique Name**: Command and Scripting Interpreter: PowerShell

## Severity
**High** - PowerShell is frequently abused by attackers for post-exploitation activities.

## False Positive Considerations
- Legitimate PowerShell scripts used for system administration
- Automated deployment scripts
- Development and testing environments
- System maintenance tasks

## Detection Logic
The rule triggers when any PowerShell executable is detected in log entries. In a production environment, you may want to add additional context such as:
- Command-line arguments analysis
- Network connections
- File system modifications
- Process parent relationships

