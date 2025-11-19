# YARA Rule 003: Web Shell Detection

## Scenario
This rule detects common web shell patterns in files. Web shells are malicious scripts that allow remote command execution on web servers.

## File Analysis
The rule searches for PHP and ASP patterns:

**PHP Indicators:**
- `<?php` tag
- `eval(` function
- `base64_decode` function
- `system(` function
- `exec(` function
- `shell_exec` function
- `passthru` function

**ASP Indicators:**
- `<%` tag
- `eval` function
- `execute` function

## MITRE ATT&CK Mapping
- **Technique ID**: T1505.003
- **Tactic**: Persistence
- **Technique Name**: Server Software Component: Web Shell

## Severity
**High** - Web shells provide persistent access and can lead to further compromise.

## False Positive Considerations
- Legitimate PHP/ASP scripts with similar patterns
- Content management systems
- Framework code
- Development environments
- Administrative tools

## Detection Logic
The rule triggers when:
- PHP tag is found AND 2+ suspicious functions are present
- OR ASP tag is found AND 2+ suspicious functions are present

## Usage Notes
Web shells are commonly used in web application attacks. This rule helps identify potentially malicious scripts, but legitimate code may also match. Review file location and context.

