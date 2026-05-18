# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MailAccess, please report it responsibly using **GitHub's private security advisory** feature:

1. Go to the **Security** tab of this repository.
2. Click **"New draft security advisory"**.
3. Describe the issue — include steps to reproduce, affected versions, and potential impact.

We aim to acknowledge reports within **72 hours** and provide a remediation timeline within **7 days**.

**Do not open a public GitHub issue for security vulnerabilities.**

---

## Scope

### In scope

- Remote code execution, command injection, or server-side request forgery (SSRF) in the backend
- Authentication bypass when `MAILACCESS_API_KEY` is configured
- SQL injection or data exposure through the API or WebSocket
- Path traversal in export or file-handling code
- Insecure default configurations that expose sensitive data to unauthenticated callers

### Out of scope

- Vulnerabilities in third-party APIs that MailAccess queries (HIBP, SerpAPI, Hunter.io, Shodan, etc.) — report those to the respective services directly
- Denial-of-service via excessive unauthenticated API calls — rate limiting and network-level protection are the operator's responsibility
- Issues that require physical access to the server
- Social engineering attacks
- Findings from automated scanners submitted without a working proof of concept

---

## Supported Versions

Security fixes are applied to the latest release only. We do not backport patches to older versions.
