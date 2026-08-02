# Contributing to llm-security-checklist

Thanks for your interest! This project welcomes contributions.

## What we're looking for

- **New checks** — AI-specific security tests not yet covered (see roadmap below)
- **Better detection** — reduce false positives/negatives in existing checks
- **Documentation** — clearer remediation guidance, more examples
- **Bug fixes** — edge cases, timeout handling, encoding issues

## Rules

1. **Pure Python stdlib only.** No pip installs. No third-party packages. This is a hard constraint — the scanner must run on any machine with Python 3.9+ and nothing else.
2. **No false positives.** Every check must have real detection logic (canary verification, entropy filtering, signature matching). No "print warning" checks.
3. **Structured output.** Every check returns a `CheckResult` with severity, evidence, and remediation. Follow the existing pattern in `scanner.py`.
4. **Tests required.** Add test cases to `tests/test_scanner.py`. Use obviously fake values (string concatenation for secrets) to avoid GitHub secret scanning false positives.
5. **No real targets.** Never run the scanner against systems you don't own or have explicit authorization to test.

## Adding a new check

1. Create a function `check_your_check(client: HttpClient, config: ScanConfig) -> CheckResult`
2. Register it in the `CHECKS` list at the bottom of `scanner.py`
3. Add test cases (both positive and negative)
4. Update the README table
5. Submit a PR with a clear description of what it detects and why

## Roadmap (requested checks)

- [ ] Multi-turn prompt injection detection (conversation-level)
- [ ] RAG poisoning detection (document chunk analysis)
- [ ] JWT manipulation testing (algorithm confusion, role escalation)
- [ ] GraphQL introspection + injection
- [ ] WebSocket security (if LLM uses WS transport)
- [ ] Model-specific jailbreak detection (GPT-4, Claude, Gemini patterns)

## Code style

- Type hints on all functions
- Docstrings on all public functions
- `LOG.debug()` for verbose output, not `print()`
- Max line length: 100 chars
- Follow existing naming: `check_*` for checks, `_helper` for private functions

## License

MIT. By contributing, you agree your code is released under the same license.

## Questions?

Open an issue or email yan@elarab.tech.
