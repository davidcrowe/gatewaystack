# Security Policy for GatewayStack

GatewayStack is an open-source **agentic control plane** for user-scoped AI governance.  
We take security seriously and appreciate responsible disclosure of vulnerabilities.

---

## Supported Versions

GatewayStack is under active development. We currently provide security fixes for:

- The latest commit on the `main` branch
- The most recent tagged release

If you're using an older tag or a fork, please try to reproduce on `main` before reporting.

---

## Reporting a Vulnerability

If you believe you’ve found a security vulnerability in GatewayStack or any of the
`@gatewaystack/*` packages, please report it **privately**:

- **GitHub:** Use the **“Report a vulnerability”** link in the repository’s **Security** tab  
  (if available in your account)

Please include as much detail as possible:

- A clear **description** of the issue and potential impact
- **Steps to reproduce** (code, configuration, or requests)
- Any relevant **logs**, stack traces, or screenshots
- The **commit hash / version** you tested against
- Your environment (Node.js version, OS, package versions)

Please **do not** open a public GitHub issue for sensitive security reports.

---

## Coordinated Disclosure Policy

We follow a responsible / coordinated disclosure process:

1. You report the vulnerability to us privately.
2. We acknowledge your report within **5 business days**.
3. We work with you to:
   - Reproduce and assess impact
   - Develop and test a fix
   - Prepare an advisory and release
4. We aim to release a fix and advisory within **30 days**, depending on severity and complexity.
5. Once a fix is released, we’ll credit you (if you’d like) in the security advisory.

If you believe we have not responded in a reasonable timeframe, you may follow up on your
original report to request a status update.

---

## Scope & Expectations

You are welcome to:

- Test against your own local deployments of GatewayStack
- Review and analyze the source code
- Probe configuration and integration flows for security issues

Please **do not**:

- Access, modify, or destroy data that does not belong to you
- Perform Denial of Service (DoS) or stress tests against shared / production deployments
- Use automated scanning in a way that could degrade service for others

If you’re unsure whether something is in scope, you can email us first and ask.

---

## Bug Bounties

At this time we **do not run a formal bug bounty program** and cannot guarantee financial rewards.

We do, however, deeply appreciate security research contributions and are happy to provide:

- Acknowledgment in security advisories (with your consent)
- Public credit in the project’s documentation or release notes

---

Thank you for helping keep Gatewaystack and its users safe.
