# Attack Paths

Attack paths are first-class ChangeGate evidence objects. They explain how a planned or live-context infrastructure relationship could become an exploitable path, not just that a risky setting exists.

The v1 model supports two categories:

* `public_to_sensitive_data`: a public entrypoint can reach a sensitive datastore, secret, or key.
* `iam_privilege_escalation`: a principal can reach admin or sensitive access through high-signal IAM actions such as pass-role, assume-role, or function/service update.

The detector commands are available through `changegate attack-paths`, and high-confidence attack paths are integrated into scan, impact, review comment, and audit-bundle output when attack-path policy is enabled.

```bash
changegate attack-paths --plan tfplan.json
changegate attack-paths --plan tfplan.json --to-sensitive-data
changegate attack-paths --plan tfplan.json --principal aws_iam_role.github_actions
changegate attack-paths --plan tfplan.json --format json --out attack-paths.json
changegate attack-paths --plan tfplan.json --format dot --out attack-paths.dot
changegate attack-paths --plan tfplan.json --format mermaid --out attack-paths.mmd
changegate attack-paths visualize --plan tfplan.json --out attack-paths.html
```

DOT and Mermaid output are intended for teams that already publish diagrams in docs or CI artifacts. `attack-paths visualize` writes a self-contained interactive HTML file with highlighted path edges, role filters, search, and a node evidence inspector. It is the preferred human review artifact when JSON is too dense for pull-request review.

Public-to-sensitive detection is available as the first v1 detector. It uses the blast-radius graph to find public entrypoint paths that pass through a workload and reach a sensitive asset. High-confidence paths to sensitive data block by default; medium-confidence paths warn. Public paths to workloads without sensitive downstream context warn unless the entrypoint is explicitly marked as expected public through tags or cloud context compensating controls such as `expected_public_tls_edge`, `edge_tls`, `waf`, `cloudfront_oac`, or `ip_allowlist`.

IAM privilege-escalation detection is also available as a v1 detector. It normalizes IAM action wildcards, service wildcards, resource wildcards, explicit deny statements, and complex conditions. The detector focuses on high-signal paths: `iam:PassRole` plus Lambda/ECS mutation, `sts:AssumeRole` to admin or sensitive roles, Lambda code update into privileged execution roles, and ECS service update into task roles with sensitive data access. Complex conditions or explicit deny ambiguity reduce confidence and produce warnings rather than high-confidence blocks.

## Contract

Attack path JSON uses schema version 1 and is documented by [`schemas/attack-paths.schema.json`](../schemas/attack-paths.schema.json).

```json
{
  "version": 1,
  "paths": [
    {
      "id": "attack-path-public-admin",
      "type": "public_to_sensitive_data",
      "title": "Public admin service reaches customer database",
      "severity": "critical",
      "confidence": "high",
      "decision": "block",
      "entrypoint": "aws_lb.admin",
      "target": "aws_db_instance.customer",
      "steps": [
        {
          "from": "internet",
          "to": "aws_lb.admin",
          "action": "public HTTP ingress",
          "edge_type": "routes_to",
          "explanation": "internet-facing load balancer accepts public traffic"
        }
      ]
    }
  ]
}
```

## Policy Eligibility

Attack paths are deterministic evidence. They can affect deployment decisions only when attack path analysis is enabled and the path confidence is high. Medium-confidence paths can be rendered as warnings when explicitly configured, but they should not create high-confidence blocking decisions.

This keeps ChangeGate’s enforcement posture conservative while still giving reviewers useful context for ambiguous paths.

## Current Scope

Attack Path v1 is intentionally narrow. It does not attempt to be a full CSPM pathfinding engine. It focuses on high-signal infrastructure changes that are practical to gate before apply:

* public entrypoint to workload to sensitive datastore, secret, or key
* principal to `iam:PassRole`, `sts:AssumeRole`, Lambda update, or ECS update paths that reach admin or sensitive access

When graph or IAM evidence is ambiguous, detectors lower confidence and produce warning-oriented evidence instead of pretending the path is certain.
