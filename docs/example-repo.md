# Example Repository Layout

A realistic ChangeGate-enabled repository can look like this:

```text
repo/
├── .github/workflows/changegate.yml
├── .changegate/
│   ├── baseline.json
│   └── waivers.yaml
├── infra/
│   ├── prod/
│   │   ├── main.tf
│   │   └── .changegate.yaml
│   └── network/
│       ├── main.tf
│       └── .changegate.yaml
└── docs/security/changegate-rollout.md
```

Each Terraform root has its own policy when ownership differs. Shared baselines and waivers can live at the repo root when the same security team reviews exceptions.

Minimal CI command:

```bash
terraform -chdir=infra/prod plan -out=tfplan
terraform -chdir=infra/prod show -json tfplan > infra/prod/tfplan.json
changegate scan --plan infra/prod/tfplan.json --policy infra/prod/.changegate.yaml --audit-bundle changegate-audit.zip
```

See [GitHub Actions](github-actions.md), [GitLab CI](gitlab-ci.md), and [monorepos](monorepo.md) for complete examples.
