# Security policy

## Project maturity

ThreatVeil is an **experimental research codebase**. It is not offered as a hosted service,
has no supported production deployment, and has not had an independent penetration test,
formal verification or compliance audit. The engineering controls described in
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) are tested, but they are not a guarantee.
Do not use ThreatVeil to make real authorization decisions for consequential systems.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| Latest `v0.x` release | Yes, fixed forward on `main` |
| Older releases | No |

There are no maintained release branches and no backported fixes.

## Reporting a vulnerability

Please report privately, not in a public issue, pull request or discussion.

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Include the affected commit, the steps to reproduce, and the
impact you believe it has. Do not include real credentials or personal data.

Maintenance is best effort. There is no bug bounty and no guaranteed response time; we aim to
acknowledge reports within 14 days. Please allow a reasonable period for a fix before public
disclosure, and tell us if you intend to publish.

## What qualifies

Examples that are in scope:

- bypassing authentication, session, CSRF or API-token boundaries;
- reading or writing another tenant's data (row-level security or query scoping bypass);
- making ThreatVeil report a claim as supported, current or cleared without qualified
  evidence, or forging, replaying or mis-binding evidence to a different system state;
- bypassing Ed25519 DSSE signature verification for receipts, passports or change records,
  or making a verifier trust an embedded key;
- server-side request forgery, redirect or DNS-rebinding escapes in target transport;
- secrets leaking into logs, API responses, exports, images or the repository;
- local sign-in (`TV_LOCAL_AUTH`) becoming reachable from a non-loopback peer, or enabled
  outside `local`/`test` environments;
- supply-chain weaknesses in the build, lockfiles, Dockerfiles or CI workflows.

Usually out of scope:

- deliberately running the local stack with local identity exposed to a network (documented
  as unsafe);
- the content of synthetic fixtures and demonstration data;
- findings that require an already-malicious operator with database-owner or host access;
- the Terraform under `infra/` in configurations it was never applied or accepted in (reports
  are still welcome as ordinary issues);
- missing hardening headers or best-practice suggestions without a concrete impact (open an
  ordinary issue instead).

## Secrets in this repository

The repository and its history were scanned with gitleaks before publication and no secrets
were found. Every credential in this repository is a placeholder or an obviously local test
value (for example `ephemeral-ci-only-not-a-production-secret`). If you find anything that
looks like a real credential, report it privately as above.
