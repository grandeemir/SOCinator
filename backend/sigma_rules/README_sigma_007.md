# Sigma Rule 007: Data Exfiltration via Network

## Scenario
This rule detects large data transfers that may indicate data exfiltration. Attackers often exfiltrate sensitive data after compromising systems.

## Log Analysis
The rule searches for:
- Large byte transfers (>100MB)
- `large_transfer` indicators
- `data_exfiltration` patterns

## MITRE ATT&CK Mapping
- **Technique ID**: T1041
- **Tactic**: Exfiltration
- **Technique Name**: Exfiltration Over C2 Channel

## Severity
**Medium** - Data exfiltration can result in data breaches and compliance violations.

## False Positive Considerations
- Legitimate backups
- Large file transfers
- Software updates
- Media file transfers
- Database exports

## Detection Logic
The rule triggers on large data transfers. Consider:
- Transfer size thresholds
- Destination IP addresses
- Unusual protocols (DNS, ICMP tunneling)
- Off-hours transfers
- Data volume anomalies
- Unusual destinations (external IPs, cloud storage)

