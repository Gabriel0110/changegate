# OpenTofu

ChangeGate reads OpenTofu plan JSON the same way it reads Terraform plan JSON.

```bash
tofu init
tofu plan -out=tfplan
tofu show -json tfplan > tfplan.json
changegate scan --plan tfplan.json
```

The normalized plan model records the tool as `opentofu` when OpenTofu metadata is present.

All output formats, policies, baselines, waivers, audit bundles, and custom rules work with OpenTofu plans:

```bash
changegate scan --plan tfplan.json --policy .changegate.yaml --audit-bundle changegate-audit.zip
```
