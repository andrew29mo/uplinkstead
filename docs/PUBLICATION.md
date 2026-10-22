# Public release checks

Uplinkstead was made public on 2026-10-22 with explicit owner authorization.
GitHub recognizes the repository's MIT license. No package registry release was made.

## Implementation evidence

The tested implementation is commit `b2df3be919f819e6d4cbb8672107c2dcc51ad902`.
The [licensing validation](../reviews/licensing/README.md) retains macOS and Linux
results for the same source fingerprint: 81 portable tests on each platform,
27 isolated Linux VM cases and 36 rejected report corruptions. The report verifier
was rerun successfully before publication, including under Python optimization.
Documentation and repository configuration changes do not rerun those VM trials.

macOS validates portable logic; Linux backend/service observations come from the
isolated VM. RSS excludes VM overhead. The controlled traffic trial establishes no
speedup, capacity or recovery SLO. Physical WANs, sudden power loss, storage repair
and boot-zero-gap protection remain untested. Historical private/pre-license
receipts are preserved, not rewritten to describe today's repository settings.

## Repository controls

Publication checks enabled secret scanning, push protection, Dependabot security
alerts/updates, weekly pip dependency checks and private vulnerability reporting.
Main rejects deletion and force pushes, requires linear history and applies those
rules to administrators. Direct normal pushes remain available for solo maintenance;
mandatory PR review and required remote CI checks are not configured.

Actions uses read-only default workflow permissions and cannot approve PR reviews.
Only GitHub-owned actions are allowed, action SHA pinning is required, and every
external contributor needs approval before fork PR workflows run. There are currently
no Actions workflows: retained local validation is not a remote CI pass.

These controls reduce exposure; they do not establish absence of vulnerabilities.
See [Security](../SECURITY.md) for private reports and [Validation](VALIDATION.md)
for the evidence boundaries.
