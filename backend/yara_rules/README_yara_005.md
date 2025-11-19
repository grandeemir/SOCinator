# YARA Rule 005: Credential Harvester Detection

## Scenario
This rule detects credential harvesting and keylogging patterns in files. Credential harvesters steal user credentials through various techniques.

## File Analysis
The rule searches for:
- `password` keyword
- `username` keyword
- `keylog` references
- `keystroke` references
- `GetAsyncKeyState` API (keyboard monitoring)
- `SetWindowsHookEx` API (hook installation)
- `credential` keyword
- `login` keyword

## MITRE ATT&CK Mapping
- **Technique IDs**: T1056, T1119
- **Tactics**: Collection, Credential Access
- **Technique Names**:
  - Input Capture (T1056)
  - Automated Collection (T1119)

## Severity
**High** - Credential harvesting can lead to unauthorized access and data theft.

## False Positive Considerations
- Legitimate password managers
- Security tools
- Authentication libraries
- Login forms and scripts
- System utilities

## Detection Logic
The rule triggers when:
- Both `password` AND `username` are found AND one keylogging indicator
- OR credential/login keywords with keylogging functions

## Usage Notes
Credential harvesters are a serious threat. This rule helps identify potential keyloggers and credential stealers. Legitimate security and authentication software may trigger false positives, so context is important.

