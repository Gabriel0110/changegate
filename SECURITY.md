# Security Policy

## Supported versions

ChangeGate supports the latest released minor version. Security fixes are released as patch versions when practical.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Report security issues through GitHub private vulnerability reporting for this repository. If private vulnerability reporting is unavailable, contact the maintainers through the private security channel listed on the repository security page.

Include:

* affected version or commit
* impact summary
* reproduction steps or proof of concept
* whether the issue affects CI/CD execution, release artifacts, policy decisions, or secret redaction

We aim to acknowledge reports within 3 business days, provide an initial assessment within 10 business days, and coordinate disclosure timing with the reporter.

## Release security

Official releases include:

* platform archives
* SHA-256 checksums
* signed checksum file
* CycloneDX SBOMs
* GitHub artifact attestations
* signed Docker images

Verification commands are published with each release artifact set.
