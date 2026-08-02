# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |

## Reporting a Vulnerability

If you find a security issue in this scanner itself (not in a target you're scanning):

1. Email yan@elarab.tech with details
2. Do NOT open a public GitHub issue
3. I'll respond within 48 hours
4. Fix timeline: 7 days for critical, 30 days for medium/low

## Responsible Use

This tool is for authorized security testing only. Before scanning any system:

- You MUST have written authorization from the system owner
- You MUST comply with applicable laws (CFAA, Computer Misuse Act, etc.)
- You MUST NOT use findings to harm systems or exfiltrate data
- Rate limiting: the scanner sends bursts of requests. Ensure your target can handle them.

The authors are not responsible for misuse of this tool.

## Disclosure Policy

Findings from using this scanner against third-party systems should be reported to the system owner, not to this repository. We do not coordinate third-party disclosures.

For vulnerabilities found in open-source projects using this scanner: follow the project's own security policy, or use responsible disclosure (30-90 day window, private communication first).
