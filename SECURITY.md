# Security Policy

## Supported versions

quic-affinity is currently pre-1.0. Security fixes are made on the `main`
branch; older snapshots and downstream forks are not maintained by this
project.

| Version | Security updates |
| --- | --- |
| `main` | Yes |
| Older snapshots | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
**Security** tab and select **Report a vulnerability** to start a private GitHub
Security Advisory. If private reporting is not enabled, contact a maintainer
privately through the hosting platform before sharing technical details.

Include, when possible:

- the affected commit or version and deployment mode;
- prerequisites, privileges, and a minimal reproducer;
- expected and observed impact;
- whether the issue affects BPF packet parsing, control-socket authorization,
  fd passing, pinned maps, restart state, or packaging;
- any proposed mitigation or patch.

Maintainers aim to acknowledge a complete report within seven days, confirm
severity and remediation scope, and coordinate disclosure after a fix is
available. Please allow a reasonable embargo for investigation and release.

## Security scope

Security-sensitive boundaries include untrusted network packets processed by
eBPF, untrusted local control clients, worker identity and lifecycle, BPF map
and state-file ownership, capability configuration, and systemd service
hardening. Reports that demonstrate denial of service, authorization bypass,
worker misrouting, stale-CID revival, unsafe file handling, or privilege
escalation are in scope.
