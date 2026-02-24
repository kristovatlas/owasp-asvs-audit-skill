# owasp-asvs-audit

[![ASVS v5.0.0](https://img.shields.io/badge/ASVS-v5.0.0-blue)](https://github.com/OWASP/ASVS/tree/v5.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![ASVS Content: CC-BY-SA 4.0](https://img.shields.io/badge/ASVS_Content-CC--BY--SA_4.0-orange)](https://creativecommons.org/licenses/by-sa/4.0/)

A Claude Code skill that performs a comprehensive security audit of your web application codebase against the [OWASP Application Security Verification Standard (ASVS) v5.0.0](https://github.com/OWASP/ASVS).

## What This Does

This skill systematically evaluates your source code against all ~350 security requirements in ASVS v5.0.0 — the industry-standard framework for verifying web application security. It covers 17 chapters spanning encoding, injection prevention, authentication, authorization, cryptography, session management, API security, and more.

The audit produces a structured report with every requirement assessed as **PASS**, **FAIL**, **N/A**, or **MANUAL_REVIEW**, complete with file paths, code snippets, confidence scores, and remediation guidance.

## What ASVS Is

The OWASP Application Security Verification Standard is a community-driven open standard maintained by the OWASP Foundation. Unlike the OWASP Top 10 (which lists common vulnerability categories), ASVS defines specific, testable security requirements that an application should satisfy. It is widely used for security audits, procurement baselines, and building security into the development lifecycle.

ASVS defines three assurance levels:

| Level | Name | Intended For |
|-------|------|-------------|
| **L1** | Opportunistic | Low-risk applications, marketing sites, blogs, prototypes |
| **L2** | Standard | Most applications — e-commerce, SaaS, apps handling PII |
| **L3** | Advanced | Banking, payments, healthcare, critical infrastructure |

This skill audits at **Level 3**, which is cumulative — it includes all L1 and L2 requirements. Every finding is tagged with its level, so you can filter results to any level you need.

## Chapters Covered

| Chapter | Title | What It Checks |
|---------|-------|---------------|
| V1 | Encoding and Sanitization | XSS, SQL injection, command injection, output encoding, deserialization |
| V2 | Validation and Business Logic | Input validation, business rule enforcement, anti-automation |
| V3 | Web Frontend Security | CSP, DOM security, client-side controls |
| V4 | API and Web Services | REST/GraphQL security, rate limiting, schema validation |
| V5 | File Processing | Upload validation, path traversal, storage security |
| V6 | Authentication | Credential handling, password policies, MFA, brute force protection |
| V7 | Session Management | Session lifecycle, token security, timeout policies |
| V8 | Authorization | Access control, privilege escalation, IDOR prevention |
| V9 | Self-Contained Tokens | JWT security, token validation, algorithm enforcement |
| V10 | OAuth and OIDC | OAuth flows, token handling, PKCE, redirect validation |
| V11 | Cryptography | Algorithm selection, key management, random number generation |
| V12 | Secure Communication | TLS configuration, certificate validation, HSTS |
| V13 | Configuration | Security headers, default credentials, environment hardening |
| V14 | Data Protection | PII handling, data classification, privacy controls |
| V15 | Secure Coding and Architecture | Dependency management, build security, architecture patterns |
| V16 | Security Logging and Error Handling | Log coverage, error handling, sensitive data in logs |
| V17 | WebRTC | Peer connection security, SRTP, TURN/STUN configuration |

## Installation

### Method 1: Git Clone (Recommended)

Clone into your project's `.claude/skills/` directory. This makes it easy to pull updates later.

```bash
# From your project root
mkdir -p .claude/skills
git clone https://github.com/kristovatlas/owasp-asvs-audit-skill.git .claude/skills/owasp-asvs-audit
```

To update later:

```bash
git -C .claude/skills/owasp-asvs-audit pull
```

### Method 2: Manual Download

For air-gapped environments or if you prefer not to use git submodules:

1. Download the [latest release](https://github.com/kristovatlas/owasp-asvs-audit-skill/releases) or clone the repo to a temporary location.
2. Copy `SKILL.md` and the `sections/` directory into `.claude/skills/owasp-asvs-audit/` in your project.

```bash
mkdir -p .claude/skills/owasp-asvs-audit
cp SKILL.md .claude/skills/owasp-asvs-audit/
cp -r sections/ .claude/skills/owasp-asvs-audit/sections/
```

### Resulting Structure

After installation, your project should have:

```
your-project/
├── .claude/
│   └── skills/
│       └── owasp-asvs-audit/
│           ├── SKILL.md
│           └── sections/
│               ├── V01-encoding-and-sanitization.md
│               ├── ...
│               └── V17-webrtc.md
└── (your project files)
```

## Usage

From Claude Code, ask:

```
Run the OWASP ASVS audit on this project
```

The skill will:

1. **Discover** your project — languages, frameworks, dependencies, architecture, existing security measures.
2. **Determine applicability** — skip chapters that don't apply (e.g., WebRTC for a REST API, OAuth for an app with simple session auth).
3. **Audit each chapter sequentially** — evaluating every requirement against your source code with detailed evidence.
4. **Write intermediate results** to `asvs-audit-results/` as it progresses (so it can resume if interrupted).
5. **Generate a final report** — both `report.json` (machine-readable) and `report.md` (human-readable).

### Scoping to Specific Chapters

You can also run a subset:

```
Run the OWASP ASVS audit — only V1 (Encoding and Sanitization) and V6 (Authentication)
```

### Filtering by Level

The report always includes all levels, but you can ask for a filtered view:

```
Run the OWASP ASVS audit at Level 2 only
```

This still evaluates everything but only reports on L1 and L2 requirements.

## Output

### Report Structure

The Markdown report (`asvs-audit-results/report.md`) is organized as:

1. **Executive Summary** — total pass/fail counts, compliance percentages by level, critical finding count.
2. **Critical Findings (High Confidence)** — FAIL findings with confidence ≥ 0.8, sorted by severity. These are the issues to fix first.
3. **Additional Findings (Lower Confidence)** — FAIL findings with confidence < 0.8. These need human verification but are still likely issues.
4. **Manual Review Required** — requirements that cannot be fully verified from source code alone (e.g., TLS configuration, deployment settings, operational procedures).
5. **Detailed Results by Chapter** — every requirement with its full assessment.

### Finding Format

Each finding includes:

- **ASVS requirement ID and text** — exactly as specified in the standard
- **Status** — PASS, FAIL, N/A, or MANUAL_REVIEW
- **Confidence score** (0.0–1.0) — how certain the auditor is about this finding
- **Evidence** — specific file paths, line numbers, and code snippets
- **Remediation guidance** — concrete steps to fix the issue, with references

### Confidence Scores

| Range | Meaning |
|-------|---------|
| 0.9–1.0 | Unambiguous evidence (e.g., `os.system(user_input)`) |
| 0.7–0.89 | Strong indicators with some ambiguity |
| 0.5–0.69 | Circumstantial — complex control flow or indirect patterns |
| 0.0–0.49 | Largely inferential — requires human verification |

## Limitations

This is a **static source code analysis** tool. It is very good at what it can see, but there are things it cannot verify:

- **Runtime behavior** — race conditions, timing attacks, actual TLS handshake configuration.
- **Infrastructure and deployment** — server hardening, network segmentation, WAF rules, cloud IAM policies.
- **Dynamic application testing** — vulnerabilities that only manifest under specific runtime conditions or input sequences.
- **Third-party service configuration** — OAuth provider settings, email service configuration, CDN security headers.

Requirements that fall outside of static analysis are flagged as `MANUAL_REVIEW` with a description of what was checked and what remains to be verified by a human.

**This skill does not replace a professional security assessment.** It provides a thorough, structured first pass that significantly reduces the work needed for a formal ASVS verification and helps developers find and fix issues early.

## Resumability

A full audit across 17 chapters can take a while. If the process is interrupted, intermediate results are saved to `asvs-audit-results/<chapter>.json`. On the next run, completed chapters are loaded from disk and the audit resumes where it left off.

To force a fresh audit, delete the `asvs-audit-results/` directory before running.

## Discoverability

This skill follows the emerging Agent Skills open format with `SKILL.md` at the repo root for compatibility with skill aggregators and agent tools.

### GitHub Topics

If you fork this repo, consider adding these topics for discoverability:

`claude-code` `agent-skills` `SKILL.md` `code-audit` `security-review` `owasp` `asvs` `static-analysis`

## ASVS Source and Licensing

The ASVS requirement text included in this skill is sourced from [OWASP ASVS v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) and is used under the [Creative Commons Attribution-Share Alike v4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.

The skill code (SKILL.md, audit guidance, tooling) is licensed under the [MIT License](LICENSE).

This skill is not affiliated with or endorsed by the OWASP Foundation. It is an independent tool that uses the publicly available ASVS standard as its assessment framework.

## Contributing

To extend this skill:

- **Adding audit guidance:** Each section file in `sections/` contains verbatim ASVS requirements followed by "Audit Guidance" blocks. These guidance blocks contain language-specific patterns, safe/unsafe code examples, and applicability notes. Contributions of additional patterns for new languages or frameworks are welcome.
- **Updating to a new ASVS version:** When a new ASVS version is released, update the requirement tables in each section file from the official source. The audit guidance may also need updating if requirements have changed.
- **Reporting issues:** If you find a false positive pattern, a missing detection for a common vulnerability, or an error in the audit guidance, please open an issue.

## Acknowledgments

Skill created by [@kristovatlas](https://x.com/kristovatlas).

ASVS by [OWASP](https://owasp.org/).
