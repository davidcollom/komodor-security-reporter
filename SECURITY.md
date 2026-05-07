# Security Policy

## Supported Versions

This project follows a best-effort maintenance model.

| Version / Branch | Supported |
| --- | --- |
| `main` | :white_check_mark: |
| Latest tagged release | :white_check_mark: |
| Older releases | :x: |

Security fixes are developed on `main` first and may be backported to the latest tagged release when practical.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for suspected vulnerabilities.

Use one of these private channels:

1. GitHub Security Advisories (preferred):
   - Open a private report via the repository's **Security > Report a vulnerability** flow.
2. Email (if configured by maintainers):
   - Send details to the project's designated security contact.

If you are unsure whether behavior is security-related, report privately first.

## What to Include in a Report

Please include as much of the following as possible:

- A clear description of the issue and impacted component(s)
- Affected version, commit SHA, and deployment context (local, Kubernetes, Helm)
- Reproduction steps or proof of concept
- Expected impact (confidentiality, integrity, availability)
- Any known mitigations or workarounds

High-quality reports help us triage and fix issues faster.

## Response Targets

We aim for the following timelines on a best-effort basis:

- Initial acknowledgement: within 3 business days
- Triage/update: within 7 business days
- Fix or mitigation plan: as soon as reasonably possible based on severity and complexity

These targets are goals, not guarantees.

## Disclosure Process

- We will validate and triage the report privately.
- We may ask for additional detail or validation.
- Once a fix is available, maintainers will coordinate disclosure timing with the reporter when possible.
- Public advisories or release notes will credit reporters who want attribution.

## Scope and Expectations

In scope:

- Vulnerabilities in source under this repository
- Insecure default behavior in configuration, Helm templates, or container runtime posture
- Dependency vulnerabilities that are exploitable in this project context

Out of scope (unless exploit path is demonstrated):

- Vulnerabilities in third-party scanners or external services with no project-specific exploit path
- Denial-of-service requiring unrealistic attacker control of the cluster or deployment environment
- Missing security best practices without a concrete exploit scenario

## Hardening Recommendations

When deploying, keep these controls enabled:

- Run as non-root with a read-only filesystem
- Drop Linux capabilities and disable privilege escalation
- Apply least-privilege RBAC
- Restrict network egress where possible
- Keep scanner binaries and container images up to date

## Safe Harbor

We support good-faith security research intended to improve project security.

Please avoid actions that may degrade service availability, access user data, or violate applicable law. If you act in good faith and follow this policy, we will not pursue legal action for your research.
