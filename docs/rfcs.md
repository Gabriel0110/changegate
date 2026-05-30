# RFC Process

Use an RFC for changes that affect public behavior, compatibility, or the long-term architecture of ChangeGate.

## When To Write An RFC

Write an RFC for:

* new provider families
* output schema changes
* exit-code changes
* policy-pack versioning changes
* changes to default block/warn behavior
* cloud-context semantics
* new plugin or extension models
* major graph model changes
* release security model changes

Small bug fixes, documentation edits, fixture reductions, and narrow rule additions usually do not need an RFC.

## RFC Lifecycle

1. Copy `docs/rfcs/0000-template.md` to a new numbered file.
2. Fill out motivation, design, compatibility, security, alternatives, and rollout.
3. Open a pull request with the RFC only.
4. Maintainers discuss and request changes.
5. Once accepted, implementation pull requests reference the RFC.
6. If the design changes materially during implementation, update the RFC.

Accepted RFCs describe direction. They do not guarantee that a feature will ship unchanged.

## Review Criteria

Maintainers review RFCs for:

* impact on false positives
* compatibility with existing CI users
* schema and exit-code stability
* implementation complexity
* security implications
* migration and documentation quality
