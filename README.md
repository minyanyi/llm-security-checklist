# 🔒 LLM Security Checklist & Scanner

**Automated security testing for AI/LLM applications.** Find prompt injection, API key leaks, SSRF, auth bypass, and more — in one command.

```bash
python scanner.py https://your-ai-api.com --output report.json
```

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## What It Tests

| # | Check | Severity | OWASP LLM Mapping |
|---|-------|----------|-------------------|
| 1 | API Key / Secret Exposure | HIGH | LLM06: Sensitive Information Disclosure |
| 2 | Prompt Injection (system prompt leak) | HIGH | LLM01: Prompt Injection |
| 3 | Authentication Bypass (admin endpoints) | CRITICAL | LLM06 + Access Control |
| 4 | Rate Limiting (brute force protection) | MEDIUM | LLM04: Model Denial of Service |
| 5 | CORS Misconfiguration | HIGH | LLM06: Sensitive Information Disclosure |
| 6 | Security Headers | LOW | General hardening |
| 7 | SSRF / Cloud Metadata Access | CRITICAL | LLM07: Insecure Plugin Design |

## Quick Start

```bash
# No dependencies — stdlib only
git clone https://github.com/minyanyi/llm-security-checklist.git
cd llm-security-checklist

# Scan a target
python scanner.py https://api.example.com

# With proxy (Burp/mitmproxy)
python scanner.py https://api.example.com --proxy http://127.0.0.1:8080

# Save JSON report
python scanner.py https://api.example.com -o report.json
```

## Output

```json
{
  "scanner": "llm-security-checklist v1.0",
  "target": "https://api.example.com",
  "summary": {"total": 3, "critical": 1, "high": 1, "medium": 1, "low": 0},
  "findings": [...]
}
```

Exit codes: `0` = clean, `1` = high findings, `2` = critical findings.

## The Full Checklist

See [checklist.md](checklist.md) for the comprehensive 50-point AI/LLM security checklist covering:
- Prompt injection (direct + indirect)
- Insecure output handling
- Training data poisoning
- Model denial of service
- Supply chain vulnerabilities
- Sensitive information disclosure
- Insecure plugin/tool design
- Excessive agency
- Overreliance
- Model theft

## Who This Is For

- **Developers** shipping LLM features who want a quick security sanity check
- **Security teams** adding AI/LLM to their testing scope
- **Startups** preparing for SOC 2 / ISO 27001 with AI components
- **Bug bounty hunters** testing AI-powered targets

## Need a Full Assessment?

This scanner covers the basics. A professional assessment goes deeper:
- Multi-turn prompt injection chains
- Tool-calling abuse and privilege escalation
- RAG poisoning and data exfiltration
- Model-level attacks (extraction, inversion)
- Business logic flaws in AI workflows

**[Book a free 30-min AI security review →](https://ai-armor-booking.nicheminer-mail-test.workers.dev)**

Or email: yan@elarab.tech

---

## License

MIT. Use it, fork it, ship it.

## Author

**Yan** — OSCP / OSCE / CEH
AI Armor Security | [yan@elarab.tech](mailto:yan@elarab.tech)
