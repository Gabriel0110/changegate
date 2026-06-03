# Public Admin Path Demo

This demo shows ChangeGate's core differentiator: it does not only report that a resource is public. It explains the blast-radius path from a public entrypoint to a sensitive data asset and turns that evidence into a deploy decision.

The fixture models this planned change:

```text
internet -> aws_lb.admin -> aws_lb_listener.admin -> aws_lb_target_group.admin
         -> aws_ecs_service.admin -> aws_security_group.public -> aws_db_instance.customer
```

ChangeGate blocks the change because a public load balancer reaches an admin ECS service with a path to a production customer database.

## Run The Demo

From the repository root:

```bash
changegate scan --plan examples/demo-public-admin-path/tfplan.json
changegate impact --plan examples/demo-public-admin-path/tfplan.json --format markdown
changegate attack-paths --plan examples/demo-public-admin-path/tfplan.json --format markdown
changegate graph path \
  --plan examples/demo-public-admin-path/tfplan.json \
  --from aws_lb.admin \
  --to aws_db_instance.customer
```

The demo also includes pre-generated outputs in [outputs](outputs):

| Artifact | Purpose |
| --- | --- |
| [scan.md](outputs/scan.md) | Full Markdown scan report with findings, evidence, remediation, and fingerprints. |
| [security-impact.md](outputs/security-impact.md) | Review-friendly Security Impact Statement. |
| [pr-comment.md](outputs/pr-comment.md) | Condensed PR/MR comment body. |
| [attack-paths.md](outputs/attack-paths.md) | Deterministic attack-path evidence. |
| [graph-path.mmd](outputs/graph-path.mmd) | Mermaid graph path source for docs and markdown systems. |
| [graph-path.html](outputs/graph-path.html) | Self-contained interactive graph visualization. |
| [attack-paths.html](outputs/attack-paths.html) | Self-contained interactive attack-path visualization. |

The rendered SVG used by the README is [docs/assets/demo/public-admin-path.svg](../../docs/assets/demo/public-admin-path.svg).

## Regenerate Outputs

```bash
changegate scan --plan examples/demo-public-admin-path/tfplan.json --format markdown --out examples/demo-public-admin-path/outputs/scan.md || true
changegate impact --plan examples/demo-public-admin-path/tfplan.json --format markdown --out examples/demo-public-admin-path/outputs/security-impact.md || true
changegate scan --plan examples/demo-public-admin-path/tfplan.json --format pr-comment --out examples/demo-public-admin-path/outputs/pr-comment.md || true
changegate attack-paths --plan examples/demo-public-admin-path/tfplan.json --format markdown --out examples/demo-public-admin-path/outputs/attack-paths.md || true
changegate graph path --plan examples/demo-public-admin-path/tfplan.json --from aws_lb.admin --to aws_db_instance.customer --format mermaid --out examples/demo-public-admin-path/outputs/graph-path.mmd || true
changegate graph visualize --plan examples/demo-public-admin-path/tfplan.json --view path --from aws_lb.admin --to aws_db_instance.customer --out examples/demo-public-admin-path/outputs/graph-path.html
changegate attack-paths visualize --plan examples/demo-public-admin-path/tfplan.json --out examples/demo-public-admin-path/outputs/attack-paths.html
changegate graph render --plan examples/demo-public-admin-path/tfplan.json --view path --from aws_lb.admin --to aws_db_instance.customer --render-format svg --out docs/assets/demo/public-admin-path.svg
```

The blocking commands intentionally return exit code `1`; `|| true` keeps regeneration scripts moving while preserving the real deploy-gate behavior.

