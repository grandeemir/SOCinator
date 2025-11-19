# Sigma Rule 009: Privilege Escalation Attempts

## Scenario
This rule detects attempts to escalate privileges on Linux systems. Privilege escalation allows attackers to gain higher-level access to systems.

## Log Analysis
The rule searches for:
- `sudo` command usage
- `su -` (switch user) commands
- `setuid` system calls
- `setgid` system calls

The rule triggers when more than 3 privilege escalation attempts are detected.

## MITRE ATT&CK Mapping
- **Technique ID**: T1068
- **Tactic**: Privilege Escalation
- **Technique Name**: Exploitation for Privilege Escalation

## Severity
**High** - Privilege escalation can lead to complete system compromise.

## False Positive Considerations
- Legitimate administrative tasks
- System maintenance
- Automated scripts with sudo
- Service account operations
- Development environments

## Detection Logic
The rule counts privilege escalation attempts. Consider:
- Failed sudo attempts
- Unusual user accounts
- Off-hours activity
- Multiple failed attempts
- Successful escalations from non-admin users

