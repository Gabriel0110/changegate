# Decision Model

ChangeGate separates finding severity, confidence, and final deployment decision.

Severity describes impact. Confidence describes evidence quality. Decision describes enforcement.

## Severity

| Severity | Meaning |
| --- | --- |
| `critical` | Material risk likely to expose sensitive assets or enable privilege escalation. |
| `high` | Material risk requiring security review or default CI block in production. |
| `medium` | Meaningful risk, but context-dependent. |
| `low` | Hygiene issue or defense-in-depth gap. |
| `info` | Useful metadata, not a risk by itself. |

## Confidence

| Confidence | Meaning |
| --- | --- |
| `high` | Strong evidence from the plan graph and/or explicit cloud context. |
| `medium` | Likely risk but missing some contextual proof. |
| `low` | Heuristic signal only. |
| `unknown` | The tool cannot establish enough context. |

## Deployment Decisions

| Decision | Meaning |
| --- | --- |
| `allow` | Scan completed and no policy-blocking risk exists. |
| `warn` | Risk exists, but policy does not block deployment. |
| `block` | One or more findings violate the policy gate. |
| `error` | Scan could not complete reliably. |

The default policy blocks only findings at or above `high` severity and `high` confidence.

## Enforcement Modes

| Mode | Behavior |
| --- | --- |
| `block` | Return exit code `1` when policy produces a `block` decision. |
| `warn` | Report would-block findings, but return exit code `0` when the scan completes. |
| `audit` | Report findings without enforcement. |

## Finding Contract

Each finding should include:

* Stable ID.
* Rule ID.
* Rule name.
* Resource address.
* Provider.
* Severity.
* Confidence.
* Decision contribution.
* Evidence list.
* Remediation guidance.
* Fingerprint.

## Fingerprint Inputs

Finding fingerprints should remain stable across harmless line changes.

Include:

* Rule ID.
* Resource address.
* Provider.
* Risk category.
* Normalized evidence type.
* Relevant configuration path.
* Environment.
* Policy pack version.

Avoid:

* Line number only.
* Raw JSON path only.
* Human-readable message.
* Timestamp.
* Random ordering.

## Suppression Contract

Suppressed and downgraded findings must remain visible in machine-readable output with the reason for suppression or downgrade.

Suppression must not delete evidence. It changes enforcement, not history.
