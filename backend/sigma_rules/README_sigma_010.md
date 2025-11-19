# Sigma Rule 010: Malicious Process Injection

## Scenario
This rule detects process injection techniques used by malware to hide malicious code within legitimate processes. Process injection is a common defense evasion technique.

## Log Analysis
The rule searches for:
- `CreateRemoteThread` API calls
- `VirtualAllocEx` API calls
- `WriteProcessMemory` API calls
- `NtCreateThreadEx` system calls

## MITRE ATT&CK Mapping
- **Technique ID**: T1055
- **Tactic**: Defense Evasion, Privilege Escalation
- **Technique Name**: Process Injection

## Severity
**High** - Process injection is used by advanced malware to evade detection.

## False Positive Considerations
- Legitimate debugging tools
- Security software
- Application frameworks
- Development tools
- System utilities

## Detection Logic
The rule triggers on process injection API calls. Monitor:
- Cross-process memory operations
- Unusual process relationships
- Injection into system processes
- Code execution in remote processes
- Memory protection changes

