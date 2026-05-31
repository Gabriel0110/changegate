# Attack Paths

Attack paths are first-class ChangeGate evidence objects. They explain how a planned or live-context infrastructure relationship could become an exploitable path, not just that a risky setting exists.

The v1 model supports two categories:

* `public_to_sensitive_data`: a public entrypoint can reach a sensitive datastore, secret, or key.
* `iam_privilege_escalation`: a principal can reach admin or sensitive access through high-signal IAM actions such as pass-role, assume-role, or function/service update.

The detector commands are implemented in later Review Intelligence tranches. The model, JSON contract, Markdown renderer, and policy eligibility helpers are available now for the detector and CLI work.

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
