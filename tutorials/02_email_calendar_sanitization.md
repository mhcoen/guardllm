# Tutorial 02: Sanitize Unknown Email and Calendar Inputs

Script:
- `tutorials/02_email_calendar_sanitization.py`

What it demonstrates:
1. Treat email/calendar payloads as `UNTRUSTED`.
2. Use source-specific `SecurityContext` values (`email_content`, `calendar_content`).
3. Sanitize hidden HTML instructions and Unicode obfuscation before downstream use.

Run:

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python tutorials/02_email_calendar_sanitization.py
```
