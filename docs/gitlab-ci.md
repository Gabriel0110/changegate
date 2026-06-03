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
    CHANGEGATE_VERSION: v0.2.0
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
    - changegate scan --plan tfplan.json --format json --out "${CI_PROJECT_DIR}/changegate.json" --audit-bundle "${CI_PROJECT_DIR}/changegate-audit.zip" || status=$?
    - changegate scan --plan tfplan.json --format gitlab-code-quality --out "${CI_PROJECT_DIR}/gl-code-quality-report.json" || true
    - changegate scan --plan tfplan.json --format junit --out "${CI_PROJECT_DIR}/changegate.junit.xml" || true
    - changegate review gitlab --report "${CI_PROJECT_DIR}/changegate.json" --comment --code-quality-artifact gl-code-quality-report.json || true
    - exit "$status"
  artifacts:
    when: always
    paths:
      - changegate-audit.zip
      - changegate.json
    reports:
      codequality: gl-code-quality-report.json
      junit: changegate.junit.xml
```

For an audit-only rollout, add `--mode audit` to the first scan command.

The example installs a pinned ChangeGate release into the Terraform job image and verifies release checksums through the installer before scanning the generated plan JSON.

## Merge Request Review Bot

`changegate review gitlab` updates one sticky merge request note marked with `<!-- changegate-review -->`, so rerunning a pipeline updates the existing review instead of posting duplicates. It detects `GITLAB_TOKEN`, `CI_API_V4_URL`, `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, and `CI_COMMIT_SHA` in GitLab CI. Outside CI, pass `--api-url`, `--project`, `--merge-request`, and `--token env:MY_TOKEN`.

Use a masked project/group access token or bot token with the minimum permissions needed to create merge request notes. For GitLab.com, the practical permission is usually an `api`-scoped token for a bot or project access token with Reporter or Developer access to the project. Do not expose this token to untrusted fork pipelines.

Use `--dry-run` to validate configuration without calling the GitLab API:

```bash
changegate review gitlab --report changegate.json --comment --dry-run --project 123 --merge-request 456
```

The command auto-links the GitLab Code Quality artifact when `CI_PROJECT_URL` and `CI_JOB_ID` are available. Pass `--code-quality-url` to provide an explicit artifact URL, or `--gitlab-code-quality-link=false` to suppress the automatic link.

For external merge requests, split plan generation and commenting. Run Terraform/OpenTofu and ChangeGate scans with read-only credentials, store `changegate.json` as a pipeline artifact, and post the merge request note only from trusted protected pipeline context where `GITLAB_TOKEN` is available.
