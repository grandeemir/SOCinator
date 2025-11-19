# YARA Rule 001: Generic Malware Signatures

## Scenario
This rule detects common malware signatures and patterns in files. It identifies executable files with suspicious characteristics commonly found in malware.

## File Analysis
The rule searches for:
- PE (Portable Executable) header (`MZ`)
- DOS mode message
- MD5-like hash patterns
- Command execution patterns (`cmd.exe /c`)
- PowerShell references
- Base64 encoding

## MITRE ATT&CK Mapping
- **Technique IDs**: T1055, T1059
- **Tactics**: Defense Evasion, Execution
- **Technique Names**: 
  - Process Injection (T1055)
  - Command and Scripting Interpreter (T1059)

## Severity
**High** - Generic malware can perform various malicious activities.

## False Positive Considerations
- Legitimate software may trigger on PE header detection
- Development tools using PowerShell
- System utilities with command execution
- Requires manual review for confirmation

## Detection Logic
The rule requires:
- PE header at file start (indicates executable)
- AND one of:
  - DOS mode message (legacy executable marker)
  - Command execution with PowerShell
  - PowerShell with base64 encoding (obfuscation)

## Usage Notes
This is a generic detection rule. Positive matches should be investigated further to determine if the file is actually malicious.

