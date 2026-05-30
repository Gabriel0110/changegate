# GitLab CI

ChangeGate can emit GitLab Code Quality and JUnit artifacts.

```yaml
stages:
  - validate

changegate:
  stage: validate
  image:
    name: hashicorp/terraform:1.8
    entrypoint: [""]
  variables:
    CHANGEGATE_VERSION: vX.Y.Z
    TF_IN_AUTOMATION: "true"
  before_script:
    - apk add --no-cache bash curl tar perl-utils
    - curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" -o /tmp/install-changegate.sh
    - CHANGEGATE_INSTALL_DIR=/usr/local/bin bash /tmp/install-changegate.sh
  script:
    - cd infra
    - terraform init
    - terraform plan -out=tfplan
    - terraform show -json tfplan > tfplan.json
    - status=0
    - changegate scan --plan tfplan.json --format gitlab-code-quality --out "${CI_PROJECT_DIR}/gl-code-quality-report.json" --audit-bundle "${CI_PROJECT_DIR}/changegate-audit.zip" || status=$?
    - changegate scan --plan tfplan.json --format junit --out "${CI_PROJECT_DIR}/changegate.junit.xml" || true
    - exit "$status"
  artifacts:
    when: always
    paths:
      - changegate-audit.zip
    reports:
      codequality: gl-code-quality-report.json
      junit: changegate.junit.xml
```

For an audit-only rollout, add `--mode audit` to the first scan command.

The example installs a pinned ChangeGate release into the Terraform job image and verifies release checksums through the installer before scanning the generated plan JSON.
