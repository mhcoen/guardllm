# Tutorial 02: Sanitize Unknown Email and Calendar Inputs

<!-- nav:start -->
[Home](../README.md) / [Tutorials](README.md)
<!-- nav:end -->

Script:
- `tutorials/02_email_calendar_sanitization.py`

What it demonstrates:
1. Treat email/calendar payloads as `UNTRUSTED`.
2. Use source-specific `SecurityContext` values (`email_content`, `calendar_content`).
3. Sanitize hidden HTML instructions and Unicode obfuscation before downstream use.
4. Wrap sanitized payloads in explicit untrusted isolation blocks (`<untrusted_content ...>`) so downstream steps preserve trust boundaries.

Expected behavior:
- Output content includes wrappers such as:
  - `<untrusted_content source="email_content:..."> ... </untrusted_content>`
  - `<untrusted_content source="calendar_content:..."> ... </untrusted_content>`

Run:

```bash
python tutorials/02_email_calendar_sanitization.py
```
