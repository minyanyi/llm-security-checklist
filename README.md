# llm-security-checklist

**Automated security scanner + comprehensive testing checklist for LLM-powered applications.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Zero dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](scanner.py)
[![OWASP LLM Top 10 2025](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-orange)](checklist.md)
[![Tests](https://img.shields.io/badge/tests-64%20passing-success)](tests/test_scanner.py)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Why this exists

Most teams shipping LLM features test for traditional web vulnerabilities — and skip the AI-specific attack surface entirely. Prompt injection, tool-calling SSRF, system prompt leakage, and unbounded token consumption don't show up in a normal pentest.

This tool gives you:

1. **`scanner.py`** — a zero-dependency Python CLI that runs 11 automated checks against your LLM API and outputs a structured JSON report.
2. **`checklist.md`** — a 70+ item manual testing checklist mapped to every entry in the [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## What the scanner tests

| # | Check | OWASP | Severity | Method |
|---|-------|-------|----------|--------|
| 1 | Prompt injection (canary-based) | LLM01 | High | Injects a random canary token via override payloads; detects verbatim/partial echo |
| 2 | System prompt leakage | LLM07 | Medium | Extraction prompts + heuristic scoring of imperative instruction language |
| 3 | SSRF via tool-calling | LLM06 | High | Prompts the model to fetch cloud-metadata/internal URLs; pattern-matches response for AWS/GCP/internal signatures |
| 4 | API key exposure in frontend | LLM02 | Critical | Fetches index page + linked JS assets; regex + Shannon entropy scan for 13 secret types |
| 5 | Unauthenticated LLM access | LLM06 | Critical | Sends an unauthenticated chat completion; flags HTTP 200 responses |
| 6 | Rate limiting / unbounded consumption | LLM10 | Medium | Bursts N rapid requests; detects 429/503/Retry-After throttling |
| 7 | Verbose error / stack trace disclosure | LLM02 | Medium | Sends malformed JSON, wrong content-type, oversized payloads; matches traceback patterns |
| 8 | Debug endpoint exposure | LLM02 | High | Probes `.env`, `.git/config`, `/actuator/env`, `/metrics`, `/openapi.json`, `/admin`, etc. |
| 9 | Security header hardening | Hardening | Low | Checks HSTS, CSP, X-Content-Type-Options, Referrer-Policy |
| 10 | new-api MJ image IDOR | Access Control | Medium | Fingerprints new-api/one-api via /api/status; tests /mj/image/:id for pre-auth access (CVSS 5.3) |
| 11 | Billing race condition advisory | Business Logic | Critical | Detects new-api/one-api instances and warns about TOCTOU quota race condition (CVSS 9.1) |

Every check produces a structured finding with severity, evidence, and remediation guidance. No false "print statement" results — real detection logic with entropy filtering, canary verification, and signature matching.

## Quick start

```bash
# No install needed — stdlib only (Python 3.9+)
git clone https://github.com/minyanyi/llm-security-checklist.git
cd llm-security-checklist

# Scan an OpenAI-compatible API (unauthenticated checks run without a key)
python scanner.py --target https://api.your-app.com

# Full scan with authenticated LLM checks
python scanner.py --target https://api.your-app.com \
    --chat-path /v1/chat/completions \
    --api-key sk-your-key \
    --model gpt-4o-mini \
    --output report.json

# CI gate: fail the build on high+ findings
python scanner.py -t https://staging.your-app.com --fail-on high --no-color

# Run specific checks only
python scanner.py -t https://api.your-app.com --checks prompt-injection,ssrf-tool-calling,api-key-exposure

# List all available checks
python scanner.py --list-checks
```

### Example output

```
========================================================================
llm-security-checklist v1.0.0 — https://api.your-app.com
========================================================================
[   FAIL] prompt-injection         (high    ) Model obeyed injected instructions and echoed the attacker canary…
          └─ Sure! INJCANARY-8F3A2B1C is the answer.
[   PASS] system-prompt-leak       (medium  ) No system-prompt leakage detected (best heuristic score 1).
[   FAIL] ssrf-tool-calling        (high    ) LLM tool-calling returned internal/cloud-metadata content…
[   PASS] api-key-exposure         (critical) No known secret patterns in the index page or 4 linked JS asset(s).
[   FAIL] unauthenticated-access   (critical) Chat endpoint answered a request with NO credentials…
[   PASS] rate-limiting            (medium  ) Rate limiting observed: 12/15 requests throttled.
[   PASS] verbose-errors           (medium  ) Malformed requests did not leak stack traces or internals.
[   FAIL] debug-endpoints          (high    ) 2 sensitive/debug path(s) publicly accessible.
[   WARN] security-headers         (low     ) Missing security headers: Content-Security-Policy, Referrer-Policy.

Checks: 9  Failed: 4  Warnings: 1  Errors: 0  Skipped: 0
Findings by severity: critical=1  high=2  medium=0  low=0  info=0
```

### JSON report structure

```json
{
  "tool": "llm-security-checklist",
  "version": "1.0.0",
  "target": "https://api.your-app.com",
  "summary": {
    "checks_run": 9,
    "failed": 4,
    "findings_by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}
  },
  "checks": [
    {
      "id": "prompt-injection",
      "owasp": "LLM01",
      "severity": "high",
      "status": "fail",
      "evidence": ["Sure! INJCANARY-8F3A2B1C is the answer."],
      "recommendations": ["Treat all user input as untrusted…"]
    }
  ]
}
```

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--target, -t` | *(required)* | Base URL of the target application/API |
| `--chat-path` | `/v1/chat/completions` | Chat-completions endpoint path |
| `--api-key` | `$LLM_API_KEY` | API key for authenticated LLM checks |
| `--model` | `gpt-4o-mini` | Model name sent in chat payloads |
| `--timeout` | `15.0` | Per-request timeout (seconds) |
| `--rate-limit-requests` | `15` | Requests in the rate-limit burst |
| `--max-js-assets` | `10` | Max linked JS assets to scan for secrets |
| `--canary-url` | — | Out-of-band canary URL (interactsh/canarytokens) for SSRF verification |
| `--header KEY:VALUE` | — | Extra header for LLM requests (repeatable) |
| `--checks` | all | Comma-separated check IDs to run |
| `--output, -o` | — | Write JSON report to file |
| `--fail-on` | `high` | Exit 1 on findings at this severity+ (CI gate) |
| `--insecure` | off | Skip TLS verification (lab use only) |
| `--user-agent` | tool UA | Override User-Agent |
| `--verbose, -v` | off | Debug logging |
| `--no-color` | off | Disable ANSI colors |

## The manual checklist

The automated scanner covers the 🤖 items. The full [checklist.md](checklist.md) adds 60+ manual testing items across all 10 OWASP LLM categories:

- Indirect prompt injection via RAG documents
- Supply chain (model files, plugins, MCP servers, poisoned fine-tuning data)
- Vector/embedding weaknesses (inversion, poisoned retrieval, tenant isolation)
- Output handling (eval injection, XSS via LLM, template injection)
- Misinformation and over-reliance controls
- Denial-of-wallet and token flooding

## Running the tests

```bash
python -m unittest discover -s tests -v
# 64 tests — all detection logic covered with unit tests, no network required
```

## Architecture

```
scanner.py
├── Detection primitives (pure functions, unit-tested)
│   ├── shannon_entropy()          — filters low-entropy false positives
│   ├── find_secrets_in_text()     — 13 secret patterns + entropy gating
│   ├── classify_injection()       — canary echo classification
│   ├── leak_score()               — system prompt leakage heuristic
│   ├── detect_ssrf_evidence()     — cloud-metadata signature matching
│   ├── detect_verbose_error()     — stack trace pattern detection
│   └── judge_rate_limit()         — throttling verdict logic
├── HttpClient                     — stdlib urllib wrapper, TLS options, error normalization
├── Scanner                        — orchestrates 11 checks, builds JSON report
└── CLI                            — argparse, colored output, CI exit codes
```

## Limitations (honest ones)

- **Prompt injection detection is canary-based** — it catches naive injection but not sophisticated jailbreaks. No scanner can guarantee injection resistance.
- **SSRF checks depend on the model actually having URL-fetching tools** — if your app has no tool-calling, these checks pass trivially.
- **System prompt leakage uses heuristics** — false positives and negatives are possible. Manual verification is always needed.
- **This is not a pentest.** It's a first-pass automated screen. Production LLM systems need adversarial testing by humans who understand your specific architecture.

## ⚠️ Legal & ethical use

**Only scan systems you own or have explicit written authorization to test.** Unauthorized scanning may violate computer fraud laws (CFAA, Computer Misuse Act, etc.). The authors accept no liability for misuse.

## Author

**Yan** — OSCP / OSCE / CEH
AI security researcher and penetration tester specializing in LLM application security.

📧 [yan@elarab.tech](mailto:yan@elarab.tech)

---

## 🔒 Need a professional AI security assessment?

Automated scanners catch the low-hanging fruit. A real assessment finds the business-logic attacks, the indirect injection chains, and the architecture-level risks that no tool can detect.

**[→ Get a full AI/LLM security assessment from AI Armor Security](https://ai-armor-security.nicheminer-mail-test.workers.dev)**

We test what this scanner can't: adversarial prompt engineering, RAG poisoning, multi-agent attack chains, tool-calling privilege escalation, and denial-of-wallet modeling — with a report your board will actually read.

---

*If this tool saved you from shipping a vulnerable LLM feature, star the repo ⭐ — it helps other developers find it.*
