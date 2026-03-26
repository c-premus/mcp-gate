# Security Policy

## Supported Versions

Only the latest release receives security updates. If you are running an older version, upgrade before reporting.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

To report a vulnerability:

1. **Preferred:** Use [GitHub's private security advisory](https://github.com/c-premus/mcp-gate/security/advisories/new) feature.
2. **Alternative:** Email Chris Premus directly at the address listed on his GitHub profile.

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact

You should receive an initial response within 7 days. If the issue is confirmed, a fix will be released as soon as practical, and you will be credited in the release notes (unless you prefer otherwise).

## Scope

The following are in scope for security reports:

- JWT validation bypasses (signature verification, claim checks, algorithm confusion)
- JWKS handling issues (cache poisoning, key confusion)
- Authentication or authorization bypasses
- Header injection or smuggling through the reverse proxy
- Information disclosure (tokens, internal URLs, stack traces)
- Denial of service through resource exhaustion (memory, connections)
- Dependency vulnerabilities that are exploitable in this project's context

The following are **out of scope**:

- Vulnerabilities in upstream services (Authentik, Grafana, Traefik)
- Issues that require physical access or compromised infrastructure
- Social engineering
- Denial of service through volumetric network flooding

## Bug Bounty

There is no bug bounty program for this project.
