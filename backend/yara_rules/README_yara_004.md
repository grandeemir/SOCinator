# YARA Rule 004: Obfuscated Code Detection

## Scenario
This rule detects obfuscated and encoded malicious code. Attackers use obfuscation to hide malicious functionality from security tools.

## File Analysis
The rule searches for:
- Base64 encoded content (long strings of alphanumeric characters)
- `eval(` function (code execution)
- `unescape(` function (JavaScript deobfuscation)
- `fromCharCode` function (character code conversion)
- `String.fromCharCode` function
- Hex encoding patterns (`\x00` format)

## MITRE ATT&CK Mapping
- **Technique ID**: T1027
- **Tactic**: Defense Evasion
- **Technique Name**: Obfuscated Files or Information

## Severity
**Medium** - Obfuscation is used to evade detection, but legitimate code may also be obfuscated.

## False Positives
- Legitimate obfuscated software
- Minified JavaScript code
- Packed executables
- Software protection mechanisms
- Development tools

## Detection Logic
The rule triggers when:
- Base64 content AND eval() are present
- OR eval() with deobfuscation functions
- OR multiple hex encoding patterns (3+)

## Usage Notes
Obfuscation alone is not necessarily malicious, but it's commonly used by malware. This rule helps identify suspicious patterns that warrant further investigation.

