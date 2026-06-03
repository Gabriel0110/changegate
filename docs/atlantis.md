# Atlantis

Atlantis can run ChangeGate as a custom workflow after producing Terraform plan JSON.

```yaml
version: 3
projects:
  - dir: infra/prod
    workflow: changegate

workflows:
  changegate:
    plan:
      steps:
        - init
        - plan:
            extra_args: ["-out", "tfplan"]
        - run: terraform show -json tfplan > tfplan.json
        - run: |
            curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/v0.2.0/scripts/install.sh" -o /tmp/install-changegate.sh
            CHANGEGATE_VERSION=v0.2.0 CHANGEGATE_INSTALL_DIR="$PWD/.changegate-bin" bash /tmp/install-changegate.sh
        - run: .changegate-bin/changegate scan --plan tfplan.json --format markdown --out changegate.md --audit-bundle changegate-audit.zip
```

Atlantis comments are best kept concise. Use Markdown output for humans and keep the audit bundle as an archived CI artifact in the surrounding automation.

If your Atlantis image already includes ChangeGate, omit the install step and call `changegate` directly.

During rollout:

```bash
changegate scan --plan tfplan.json --mode audit --format markdown --out changegate.md
```
