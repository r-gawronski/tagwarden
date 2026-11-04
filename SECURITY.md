# Security Policy

## Reporting a vulnerability

Do not open a public issue for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and click **Report a vulnerability**. Include the affected version, a description, and steps to reproduce if you have them.

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (until v0.1.0) | Yes |
| Latest minor release (after v0.1.0) | Yes |
| Older releases | No |

Tagwarden is pre-1.0. Only the latest minor release receives security fixes.

## Scope

In scope:

- The operator (controller and CRDs).
- The sync Job (`sync` subcommand), including registry credentials, proxy and TLS handling.
- The Helm chart in `dist/chart` and its default RBAC and pod security settings.

Out of scope: vulnerabilities in upstream images that Tagwarden mirrors, in your registry, or in third-party dependencies with no exploitable path through Tagwarden. Report those upstream.

## Response targets

This is a small project. These are targets, not guarantees.

- Acknowledge the report within 5 business days.
- Give an initial assessment within 15 business days.
- Fix or mitigate Critical and High issues within 60 days of triage.

## Disclosure

We follow coordinated disclosure. We agree a fix and a disclosure date with the reporter. The embargo lasts at most 90 days from the report. When the fix ships, we publish a GitHub Security Advisory and request a CVE through GitHub. Reporters are credited unless they ask not to be.
