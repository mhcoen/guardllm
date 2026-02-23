# Upstream Snapshot: BIPIA

- Source repo: https://github.com/microsoft/BIPIA
- Ref: `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`
- Source export: `benchmark/email/test.jsonl`
- Imported raw records: `50`
- Mapped cases: `124`

Files:
- `raw_samples.jsonl`: raw upstream-derived entries from the export
- `mapped_cases.jsonl`: normalized benchmark cases for the harness

## License verification

The repo MIT LICENSE explicitly excludes three dataset components:
WikiTableQuestions (CC BY-SA 4.0), Stack Exchange answers (CC BY-SA 4.0),
and OpenAI Evals invoices (MIT, separately noted). Our export
(`benchmark/email/test.jsonl`) is the email injection test set, which is
not among the excluded components and is covered by the repo's MIT license.

Verified 2026-02-23 against ref `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`.
