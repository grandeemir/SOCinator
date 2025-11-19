# Sigma Rule 006: Brute Force Attack Detection

## Scenario
This rule detects multiple failed login attempts indicating brute force attacks. Brute force attacks attempt to gain unauthorized access by trying multiple password combinations.

## Log Analysis
The rule searches for:
- `Failed password` messages
- `authentication failure` messages
- `Invalid user` messages

The rule triggers when more than 5 failed attempts are detected from the same user.

## MITRE ATT&CK Mapping
- **Technique ID**: T1110
- **Tactic**: Credential Access
- **Technique Name**: Brute Force

## Severity
**Medium** - Brute force attacks can lead to unauthorized access if weak passwords are used.

## False Positive Considerations
- Legitimate user errors
- Password reset attempts
- Account lockout scenarios
- Automated system processes

## Detection Logic
The rule counts failed authentication attempts. Consider:
- Time windows (e.g., 5 attempts in 5 minutes)
- Source IP addresses
- Target usernames
- Account lockout policies
- Geographic anomalies

