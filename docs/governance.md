# Governance

ChangeGate uses a lightweight maintainer model focused on predictable policy behavior, low false positives, and transparent releases.

## Project Roles

Maintainers can merge code, cut releases, triage security reports, and accept or reject rule semantics.

Contributors can propose code, fixtures, rules, documentation, adapters, and RFCs through pull requests.

Users can report bugs, false positives, provider gaps, and rule requests through GitHub issues.

## Decision Principles

Maintainers should favor:

* deterministic behavior over clever behavior
* high-confidence blocking over broad finding volume
* stable rule IDs and schemas over convenience churn
* clear evidence and remediation over terse findings
* explicit deprecation over silent behavior changes

## Rule Stability

Stable rules are part of the public contract. Changing a stable rule's default severity, confidence, or blocking behavior requires:

* tests
* documentation updates
* `CHANGELOG.md` entry
* release notes
* maintainer approval

Experimental rules can change faster, but must be labeled as experimental in docs and release notes.

## RFCs

Major features use the RFC process in [RFCs](rfcs.md). Examples include new provider families, output schema changes, policy-pack versioning changes, cloud-context behavior, or any change that can alter CI decisions for many users.

## Security

Security reports follow the private process in [SECURITY.md](../SECURITY.md). Maintainers should avoid public discussion until a fix and disclosure plan are agreed.
