# ChangeGate Review Intelligence Implementation Plan

This document is the tranche-based implementation plan for the ChangeGate Review Intelligence update. The goal is to move ChangeGate from a strong graph-aware CLI into a production-grade infrastructure change review system that teams trust in pull requests, CI, HCP Terraform run tasks, and module regression tests.

The update focuses on six production features:

1. Security Impact Statement and PR Review Bot.
2. Blast-Radius Graph v2.
3. AWS Cloud Context Snapshot Collector.
4. Attack Path v1.
5. Self-hosted HCP Terraform Run Task Adapter. This is deferred until after the core Review Intelligence work ships.
6. Risk Tests for Terraform Modules.

## 1. Product Positioning

ChangeGate should not compete primarily as a broad IaC scanner. The core wedge is deploy decision intelligence:

```text
Terraform/OpenTofu plan
+ graph of what is actually changing
+ optional real cloud context
+ baseline and waiver governance
+ attack/blast-radius reasoning
= trusted deploy decision and review narrative
```

The final experience should make a pull request reviewer understand:

* what changed
* what became reachable
* what sensitive assets are in the blast radius
* whether risk is new, existing, worsened, resolved, or waived
* who owns the affected service
* why ChangeGate allowed, warned, blocked, or required manual approval
* what the smallest safe next step is

## 2. Non-Negotiable Design Constraints

### 2.1 Deterministic Gate

The deployment decision remains deterministic. No LLM, heuristic prose generator, or external hosted service decides `ALLOW`, `WARN`, `BLOCK`, or `MANUAL_APPROVAL_REQUIRED`.

### 2.2 Offline by Default

`changegate scan` must remain credential-free and offline unless the user explicitly passes a cloud context file or requests cloud collection.

### 2.3 Single Binary First

All core features ship in the `changegate` binary. The HCP Terraform adapter may be exposed as:

```bash
changegate run-task serve
```

and packaged as a Docker image, but it should use the same internal engine.

### 2.4 Evidence Before Enforcement

Every blocking decision must include concrete evidence:

* plan resource address
* graph path
* rule or attack path ID
* changed action
* relevant cloud context evidence when present
* confidence
* remediation or review path

### 2.5 Redaction and Secret Safety

Outputs, audit bundles, comments, logs, snapshots, and fixtures must use the existing redaction model and add tests for new fields. No secret value should appear in PR comments, HCP outcomes, JSON reports, snapshots, or test golden files.

### 2.6 Stable Machine Contracts

New JSON output must be versioned and tested with golden files. Human Markdown can evolve more freely, but the canonical JSON structures should be stable before public release.

## 3. Current Baseline

The repository already includes:

* Terraform/OpenTofu plan JSON ingestion.
* AWS graph-aware rules.
* deterministic allow/warn/block decisions.
* baselines and `--new-only`.
* waiver governance.
* Markdown, PR comment, SARIF, GitHub annotations, GitHub step summary, GitLab Code Quality, JSON, JUnit, and audit bundle output.
* external scanner imports for SARIF, Checkov, Trivy, KICS, Grype, and generic JSON.
* a graph package with shortest path and exposure helpers.
* cloud context snapshot schema and enrichment hooks.
* remediation templates and owner hints from tags.
* GitHub, GitLab, Atlantis, and Terraform Cloud documentation.

The Review Intelligence update should deepen these capabilities rather than replace them.

## 4. Target Command Surface

The final update should add or complete these user-facing commands:

```bash
changegate impact --plan tfplan.json --format markdown
changegate impact --plan tfplan.json --format json
changegate impact --plan tfplan.json --baseline .changegate/baseline.json --new-only
changegate impact --plan tfplan.json --context-file .changegate/aws-context.json

changegate graph summary --plan tfplan.json
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer
changegate graph exposure --plan tfplan.json --resource aws_ecs_service.admin
changegate graph export --plan tfplan.json --format json

changegate attack-paths --plan tfplan.json
changegate attack-paths --plan tfplan.json --principal aws_iam_role.github_actions
changegate attack-paths --plan tfplan.json --to-sensitive-data

changegate context aws snapshot --out .changegate/aws-context.json --collect
changegate context aws snapshot --out .changegate/aws-context.json --collect network,iam,data
changegate context aws validate-permissions --context-file .changegate/aws-context.json

changegate review github --report changegate.json --comment --annotations
changegate review gitlab --report changegate.json --comment

changegate run-task serve --config changegate-run-task.yaml
changegate run-task verify --payload payload.json --hmac-secret env:CHANGEGATE_RUN_TASK_HMAC

changegate test
changegate test ./changegate-tests
changegate test --update
```

Existing commands must continue to work.

## 5. Target Packages

Proposed package layout:

```text
internal/impact        Security Impact Statement model and builders
internal/review        GitHub/GitLab comment rendering and publishing
internal/graph         Graph v2 query and exposure APIs
internal/attackpath    Attack path model, detectors, and evidence
internal/cloudcontext  Snapshot schema, AWS collector, enrichment
internal/runtask       HCP Terraform run task protocol and server
internal/risktest      Module risk-test manifest parser and runner
internal/output        Formats and audit bundle expansion
internal/cli           Command wiring
```

Keep package boundaries small:

* `internal/impact` should depend on model, graph, baseline, waiver, attackpath, and output summaries.
* `internal/review` should depend on impact/output and transport clients.
* `internal/runtask` should depend on scan/impact/report execution through a narrow interface, not on CLI internals.
* `internal/cloudcontext` should keep provider-specific AWS code behind interfaces.

## 6. Tranche 0: Planning, Contracts, and Feature Flags

### Goal

Create the durable contracts and rollout switches so implementation can proceed without breaking existing users.

### Implementation

* Add `docs/review-intelligence-plan.md`.
* Add `docs/review-intelligence.md` as the user-facing feature overview once implementation begins.
* Add config feature toggles:

```yaml
review:
  enabled: true
  max_comment_findings: 10
  max_graph_paths: 5
  sticky_comment_marker: "<!-- changegate-review -->"

impact:
  include_existing_risks: true
  include_resolved_risks: true
  include_waivers: true

attack_paths:
  enabled: true
  block:
    - type: public_to_sensitive_data
      min_confidence: high
    - type: iam_privilege_escalation
      min_confidence: high
  warn:
    - type: public_to_sensitive_data
      min_confidence: medium
    - type: iam_privilege_escalation
      min_confidence: medium
```

* Keep defaults compatible until Tranche 19 enables scan-time attack path findings.
* Define experimental status for new commands in docs until test corpus is strong.

### Acceptance

* Existing `changegate scan` golden outputs remain unchanged unless explicitly extended with backward-compatible fields.
* Config schema validates new fields.
* Roadmap clearly identifies Review Intelligence as planned/active work.

### Tests

* Config parser tests for new keys.
* CLI help golden tests for new commands as they are introduced.

## 7. Tranche 1: Canonical Impact Model

### Goal

Create a structured Security Impact Statement that can power Markdown, JSON, PR comments, HCP outcomes, and audit bundles.

### Data Model

Add `internal/impact.Statement`:

```go
type Statement struct {
    Version          int
    Decision         model.Decision
    DecisionReasons  []model.DecisionReason
    Summary          Summary
    RiskMovement     RiskMovement
    TopFindings      []model.Finding
    TopGraphPaths    []GraphPathSummary
    AttackPaths      []AttackPathSummary
    Waivers          WaiverSummary
    Baseline         BaselineSummary
    Ownership        []OwnershipHint
    ReviewRequired   bool
    RequiredReviewers []ReviewerRequirement
    GeneratedAt      time.Time
}
```

Include summaries:

```go
type Summary struct {
    PlansScanned             int
    ResourcesChanged         int
    ResourcesCreated         int
    ResourcesUpdated         int
    ResourcesDeleted         int
    PublicEntrypointsAdded   int
    SensitiveAssetsTouched   int
    IAMPermissionChanges     int
    NetworkPathChanges       int
    DataPathChanges          int
}

type RiskMovement struct {
    NewCritical        int
    NewHigh            int
    NewMedium          int
    ResolvedCritical   int
    ResolvedHigh       int
    ExistingUnchanged  int
    ExistingWorsened   int
    ExistingImproved   int
    WaivedActive       int
    WaivedExpired      int
}
```

### Implementation

* Build `internal/impact` around existing `output.Report`.
* Add a builder:

```go
func Build(report output.Report, opts Options) (Statement, error)
```

* Sort all output deterministically:
  * severity descending
  * confidence descending
  * decision impact descending
  * resource address
  * rule ID
* Add stable IDs for statement sections so downstream comments can link to them.
* Add redaction at the model boundary.

### Acceptance

* `impact.Statement` can be generated from existing scan reports without rerunning scan logic.
* Output is deterministic across repeated runs.
* Sensitive values are redacted.

### Tests

* Golden JSON for a representative impact statement.
* Redaction tests with sensitive tags, secret ARNs, and policy documents.
* Sorting tests.

## 8. Tranche 2: Risk Movement and Baseline Delta

### Goal

Make adoption-friendly “new risk only” behavior visible in every review.

### Implementation

* Extend baseline diff output to classify:
  * new risk
  * existing unchanged
  * existing worsened
  * existing improved
  * resolved
* Define “worsened” as any of:
  * severity increased
  * confidence increased to high
  * decision changed from allow/warn to block
  * graph path now reaches sensitive data
  * cloud context adds stronger evidence
  * waiver no longer applies
* Define “improved” as inverse movement with stable fingerprint lineage.
* Add `risk_movement` to JSON report and impact statement.
* Preserve existing `--new-only` behavior, but make its effect explicit:

```text
Existing unchanged risk suppressed by baseline.
New high risk remains enforceable.
```

### Acceptance

* PR output can state: “New high risks: 1, existing unchanged: 34, resolved: 2.”
* `--new-only` never hides a worsened existing risk without reporting that movement.

### Tests

* Baseline diff unit tests for every movement category.
* Golden impact statement with risk movement.
* Regression test that a changed graph path turns “existing” into “worsened.”

## 9. Tranche 3: Security Impact Statement CLI

### Goal

Expose impact statements as a first-class command.

### Command

```bash
changegate impact --plan tfplan.json --format markdown
changegate impact --plan tfplan.json --format json
changegate impact --plan tfplan.json --audit-bundle impact-audit.zip
```

### Implementation

* Reuse scan loading, config, baseline, waiver, import, and cloud context paths.
* Add `internal/cli/impact.go`.
* Support repeated `--plan`.
* Support:
  * `--baseline`
  * `--new-only`
  * `--context-file`
  * `--cloud-context`
  * external scanner imports
  * `--max-findings`
  * `--max-paths`
* Do not duplicate scan logic. Extract a reusable scan engine if necessary:

```go
internal/engine.Scan(ctx, Request) (output.Report, error)
```

### Output Shape

Markdown should lead with:

```markdown
# Security Impact Statement

Decision: BLOCK
Review required: Yes

This change introduces:
- 1 public entrypoint
- 1 public-to-sensitive data path
- 2 IAM privilege-expansion paths
- 1 active waiver
```

### Acceptance

* `changegate impact` works with the same plan/config inputs as `scan`.
* Markdown is readable in GitHub, GitLab, and HCP Terraform outcome bodies.
* JSON is stable and versioned.

### Tests

* CLI golden output for help, JSON, and Markdown.
* Round-trip JSON unmarshal test.
* Multi-plan test.

## 10. Tranche 4: Blast-Radius Graph v2 Core

### Goal

Promote graph analysis from internal rule support to a flagship user-facing model.

### Graph Model Additions

Add richer node classification:

```go
type NodeKind string

const (
    NodePublicEntrypoint NodeKind = "public_entrypoint"
    NodeWorkload         NodeKind = "workload"
    NodeDataStore        NodeKind = "data_store"
    NodeSecret           NodeKind = "secret"
    NodeKMSKey           NodeKind = "kms_key"
    NodePrincipal        NodeKind = "principal"
    NodePolicy           NodeKind = "policy"
    NodeNetworkBoundary  NodeKind = "network_boundary"
)
```

Add richer edge types:

```go
EdgeRoutesTo
EdgeAllowsIngress
EdgeAllowsEgress
EdgeAttachedTo
EdgeAssumes
EdgePassesRole
EdgeGrantsPermission
EdgeReadsSecret
EdgeEncryptsWith
EdgeWritesTo
EdgeReplicatesTo
EdgeProtects
```

### AWS Coverage Target

Graph v2 should classify and connect:

* ALB/NLB/ELB
* listeners and target groups
* ECS services and task definitions
* Lambda functions
* API Gateway routes
* CloudFront distributions
* security groups and rules
* subnets, route tables, internet gateways, NAT gateways
* RDS, Aurora, OpenSearch, ElastiCache
* S3 buckets
* Secrets Manager secrets
* KMS keys
* IAM roles, policies, trust policies, instance profiles
* EKS clusters and node groups where plan data is sufficient

### Query APIs

Add:

```go
func (g *Graph) Exposure(resource ResourceID) ExposureResult
func (g *Graph) Paths(from, to ResourceID, opts PathOptions) []Path
func (g *Graph) BlastRadius(resource ResourceID, opts BlastRadiusOptions) BlastRadius
func (g *Graph) PublicEntrypoints() []ResourceID
func (g *Graph) SensitiveAssets() []ResourceID
func (g *Graph) ChangedBoundaryCrossings() []Path
```

### Acceptance

* Graph paths explain public entrypoint to workload to sensitive asset.
* Existing rules can keep using current helper APIs.
* Unknown resources are tolerated and represented without panics.

### Tests

* Unit tests for each new edge family.
* Golden graph JSON for canonical fixtures.
* Determinism test.
* Performance test for large graph path search.

## 11. Tranche 5: Graph CLI

### Goal

Expose graph analysis directly to users.

### Commands

```bash
changegate graph summary --plan tfplan.json
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer
changegate graph exposure --plan tfplan.json --resource aws_ecs_service.admin
changegate graph export --plan tfplan.json --format json
```

### Output

`graph exposure` should render:

```text
Exposure: HIGH

Public entrypoints:
  aws_lb.admin

Reachable workloads:
  aws_ecs_service.admin

Sensitive downstream assets:
  aws_db_instance.customer_prod
  aws_secretsmanager_secret.customer_db_password

Top path:
  internet -> aws_lb.admin -> aws_lb_target_group.admin -> aws_ecs_service.admin -> aws_db_instance.customer_prod
```

### Acceptance

* Graph commands are useful without running policy.
* Output supports JSON for automation.
* Missing node names return a helpful error and nearest known addresses.

### Tests

* CLI golden tests.
* JSON schema smoke test.
* Error snapshot tests for unknown resources.

## 12. Tranche 6: PR Comment Renderer v2

### Goal

Generate a polished review comment that feels like a senior infrastructure security reviewer summarized the change.

### Output Sections

The comment should include:

1. sticky marker
2. decision header
3. review summary
4. risk movement
5. top blocking findings
6. top blast-radius paths
7. attack paths
8. active/expired/unused waiver summary
9. baseline effect
10. owner hints
11. remediation summary
12. links to artifacts

### Markdown Example

```markdown
<!-- changegate-review -->

## ChangeGate Infrastructure Review: BLOCKED

This change introduces 1 blocking infrastructure risk and 1 manual review trigger.

### Security Impact

| Signal | Count |
|---|---:|
| Public entrypoints added | 1 |
| Sensitive assets reachable | 2 |
| IAM privilege expansion paths | 1 |
| New high risks | 1 |
| Existing unchanged risks | 34 |
| Resolved risks | 2 |

### Top Blast Radius

`internet -> aws_lb.admin -> aws_ecs_service.admin -> aws_db_instance.customer_prod`

Why this matters: a public admin route can reach customer production data.

### Required Action

Make the load balancer internal, restrict ingress to approved CIDRs, or add a reviewed waiver scoped to staging.
```

### Implementation

* Add `internal/review/comment.go`.
* Keep comment rendering pure and testable.
* Add configurable limits for comment size.
* Collapse long details into `<details>` blocks.
* Always include a stable hidden marker.
* Include a compact fallback if generated comment would exceed provider limits.

### Acceptance

* GitHub and GitLab Markdown render cleanly.
* Comment remains useful for clean `ALLOW` runs.
* No table exceeds reasonable mobile width.

### Tests

* Golden Markdown for allow/warn/block/manual-review.
* Size-limit truncation tests.
* Redaction tests.

## 13. Tranche 7: GitHub PR Review Bot

### Goal

Post or update a sticky ChangeGate PR comment and emit inline annotations where possible.

### Commands

```bash
changegate review github --report changegate.json --comment
changegate review github --report changegate.json --annotations
changegate review github --plan tfplan.json --comment --annotations
```

### GitHub Integration

Use:

* issue comments API for the sticky PR summary comment
* pull request review comments API for optional inline diff comments
* workflow commands for annotation fallback
* `GITHUB_STEP_SUMMARY` for job summary output

Official GitHub docs describe pull request review/comment endpoints and workflow command annotations.

### Authentication

Default environment detection:

```text
GITHUB_TOKEN
GITHUB_REPOSITORY
GITHUB_EVENT_PATH
GITHUB_SHA
GITHUB_REF
```

Support explicit flags:

```bash
--repo owner/repo
--pr 123
--commit-sha abc123
--token env:GITHUB_TOKEN
```

### Sticky Comment Algorithm

1. Render comment with marker `<!-- changegate-review -->`.
2. List PR issue comments.
3. Find existing bot/user comment containing marker.
4. Update it if found.
5. Create it if missing.
6. Include artifact links when provided.

### Inline Annotation Strategy

* Use SARIF upload for code scanning when available.
* Use workflow commands for plan-file annotations.
* Use PR review comments only when a finding maps to a changed Terraform source line.
* Avoid noisy duplicate inline comments.

### Acceptance

* Re-running CI updates one comment, not many.
* Works from `pull_request` and `pull_request_target` with documented security caveats.
* Works with minimal permissions:

```yaml
permissions:
  contents: read
  pull-requests: write
  issues: write
  security-events: write
```

### Tests

* Unit tests with fake GitHub client.
* Event parsing tests for GitHub webhook payloads.
* Golden API request tests.
* End-to-end dry-run mode that prints intended API actions.

## 14. Tranche 8: GitLab Merge Request Review Bot

### Goal

Provide the same review experience for GitLab teams.

### Commands

```bash
changegate review gitlab --report changegate.json --comment
changegate review gitlab --plan tfplan.json --comment
```

### GitLab Integration

Use:

* Merge request Notes API for sticky summary comments.
* Discussions API for optional threaded comments and resolvable diff discussions.
* GitLab Code Quality output for native widgets.

Official GitLab docs support listing, creating, updating, and deleting merge request notes; discussion endpoints support threaded notes and resolving discussions.

### Authentication

Default environment detection:

```text
GITLAB_TOKEN
CI_API_V4_URL
CI_PROJECT_ID
CI_MERGE_REQUEST_IID
CI_COMMIT_SHA
```

Support explicit flags:

```bash
--api-url https://gitlab.com/api/v4
--project 123
--merge-request 456
--token env:GITLAB_TOKEN
```

### Acceptance

* One sticky MR note is created/updated.
* Summary includes links to GitLab Code Quality artifact when known.
* Inline discussions are optional and off by default.

### Tests

* Fake GitLab server tests.
* Sticky-note marker tests.
* CI environment detection tests.

## 15. Tranche 9: Review Bot CI Templates

### Goal

Make adoption nearly copy-paste.

### Deliverables

* Update `docs/github-actions.md`.
* Update `docs/gitlab-ci.md`.
* Add examples:
  * GitHub comment-only
  * GitHub comment + SARIF + annotations
  * GitLab Code Quality + MR note
  * audit-only rollout
  * blocking rollout

### GitHub Example

```yaml
- name: Run ChangeGate
  run: |
    changegate scan --plan tfplan.json --format json --out changegate.json --audit-bundle changegate-audit.zip

- name: Post ChangeGate review
  if: always() && github.event_name == 'pull_request'
  run: changegate review github --report changegate.json --comment --annotations
  env:
    GITHUB_TOKEN: ${{ github.token }}
```

### Acceptance

* Templates install the binary; they do not assume it exists.
* Permissions are least-privilege.
* Docs explain fork PR security considerations.

## 16. Tranche 10: AWS Cloud Context Schema v2

### Goal

Expand the snapshot schema so it can represent enough real AWS state for blast-radius and attack-path enrichment.

### Schema Additions

Add top-level sections:

```json
{
  "network": {},
  "iam": {},
  "data": {},
  "compute": {},
  "edge": {},
  "relationships": []
}
```

Relationship shape:

```json
{
  "from": "arn:aws:elasticloadbalancing:...",
  "to": "arn:aws:ecs:...",
  "type": "routes_to",
  "source": "aws_describe_target_groups",
  "confidence": "high"
}
```

Resource identity shape:

```json
{
  "terraform_address": "aws_lb.admin",
  "arn": "arn:aws:elasticloadbalancing:...",
  "account_id": "123456789012",
  "region": "us-east-1",
  "tags": {
    "owner": "platform",
    "service": "admin"
  },
  "sensitivity": {
    "data": true,
    "reason": "tag:data_classification=restricted"
  }
}
```

### Compatibility

* Continue loading v1 snapshots.
* Add migration/normalization from v1 to v2 in memory.
* Write v2 for new collectors.

### Acceptance

* Snapshot loader accepts v1 and v2.
* Redaction applies to all new fields.
* Enrichment can join Terraform addresses to AWS ARNs using tags, IDs, and known attributes.

### Tests

* v1 compatibility tests.
* v2 schema golden tests.
* Redaction tests.

## 17. Tranche 11: AWS Snapshot Collector Foundation

### Goal

Make `changegate context aws snapshot --collect` collect real read-only AWS inventory.

### Dependencies

Use AWS SDK for Go v2. Add only the service clients required for the first slice:

* STS
* EC2
* ELBv2
* ECS
* Lambda
* IAM
* RDS
* S3
* Secrets Manager
* KMS
* API Gateway v2 where needed

### Collector Design

```go
type Collector interface {
    Collect(ctx context.Context, req Request) (cloudcontext.Snapshot, []model.Diagnostic, error)
}

type AWSClientSet interface {
    EC2() EC2API
    ELBV2() ELBV2API
    IAM() IAMAPI
    ...
}
```

Use interfaces around AWS clients for testability.

### CLI

```bash
changegate context aws snapshot --out aws-context.json --collect
changegate context aws snapshot --out aws-context.json --collect network,edge,data
changegate context aws snapshot --out aws-context.json --regions us-east-1,us-west-2
changegate context aws snapshot --out aws-context.json --profile prod-readonly
```

### Safety

* No write APIs.
* No secret value APIs.
* Do not call `secretsmanager:GetSecretValue`.
* Do not call decrypt APIs.
* Redact policy documents where necessary but preserve action/resource shapes.
* Honor context cancellation and timeouts.

### Acceptance

* Collector succeeds with least-privilege read-only permissions.
* Partial permission failures produce diagnostics, not crashes.
* Snapshot is deterministic after sorting.

### Tests

* Unit tests with fake AWS clients.
* Permission-denied diagnostic tests.
* Snapshot redaction tests.
* Timeout/cancellation tests.

## 18. Tranche 12: AWS Network and Edge Collection

### Goal

Collect enough network and edge state to distinguish expected public web exposure from risky public admin/data paths.

### AWS APIs

Collect:

* VPCs
* subnets
* route tables
* internet gateways
* NAT gateways
* security groups and rules
* network interfaces
* ALBs/NLBs
* listeners
* listener rules
* target groups
* target health and registered targets where available
* CloudFront distributions if used as edge
* API Gateway routes where discoverable

### Relationships

Create relationships:

* internet -> internet-facing ALB/NLB
* ALB listener -> target group
* target group -> ECS/Lambda/instance/IP target
* subnet -> route table
* route table -> internet gateway
* security group -> security group ingress/egress
* network interface -> attached resource

### Acceptance

* Snapshot can tell whether a Terraform resource is actually internet-routable.
* Snapshot can tell whether a security group is attached to any workload.
* Scan can downgrade “public HTTPS” when it is expected public edge with controls.
* Scan can upgrade public exposure when live routing contradicts plan assumptions.

### Tests

* Fake AWS inventory fixtures.
* Public subnet with IGW route test.
* Private subnet with NAT-only test.
* ALB to ECS target group test.

## 19. Tranche 13: AWS IAM, Compute, and Data Collection

### Goal

Collect enough IAM/data/compute state for attack path v1 and sensitive blast-radius paths.

### IAM Collection

Collect:

* roles
* assume role policies
* attached managed policies
* inline policies
* instance profiles
* OIDC providers
* policy document action/resource/condition shapes

Do not collect credentials or secrets.

### Compute Collection

Collect:

* ECS clusters/services/task definitions
* Lambda functions and execution roles
* EC2 instances and instance profiles
* EKS clusters and node roles where feasible

### Data Collection

Collect:

* RDS instances and clusters
* S3 buckets and public access block settings
* Secrets Manager secret metadata
* KMS key metadata and key policies
* OpenSearch/ElastiCache metadata if included in v1 scope

### Relationships

Create:

* workload -> role
* role -> policy
* policy -> action/resource
* workload -> secret
* workload -> KMS key
* workload -> datastore
* datastore -> KMS key

### Acceptance

* Snapshot can identify sensitive assets based on tags, resource type, and known relationships.
* Snapshot can detect broad trust policies and cross-account assumability.
* Snapshot can support the first IAM attack paths.

### Tests

* IAM policy parser tests.
* Trust policy tests.
* Redaction tests for policy documents and ARNs.

## 20. Tranche 14: Cloud Context Graph Merge

### Goal

Merge plan graph and cloud context graph into one review graph without losing provenance.

### Implementation

* Add `graph.MergeContext(planGraph, contextSnapshot)`.
* Preserve source:

```go
type EdgeSource string

const (
    SourcePlan EdgeSource = "plan"
    SourceCloudContext EdgeSource = "cloud_context"
    SourceInferred EdgeSource = "inferred"
)
```

* Add confidence to edges:

```go
High: explicit plan or live API relationship
Medium: inferred from tags/IDs
Low: heuristic fallback
```

* Add conflict diagnostics:
  * plan says private, cloud says public
  * plan has no attachment, cloud has active attachment
  * Terraform-managed resource attached to unmanaged live resource

### Acceptance

* Reports can show whether a graph path came from plan, live context, or both.
* Conflicts can upgrade findings when they materially increase risk.
* Missing cloud context never creates false confidence.

### Tests

* Merge tests for matching by Terraform address.
* Merge tests for matching by ARN and ID.
* Conflict tests.
* Determinism tests.

## 21. Tranche 15: Attack Path Model

### Goal

Define attack paths as first-class evidence objects.

### Data Model

```go
type AttackPath struct {
    ID          string
    Type        Type
    Title       string
    Severity    model.Severity
    Confidence  model.Confidence
    Decision    model.Decision
    Principal   string
    Entrypoint  string
    Target      string
    Steps       []Step
    Evidence    []model.Evidence
    Mitigations []string
    References  []string
}

type Step struct {
    From        string
    To          string
    Action      string
    EdgeType    graph.EdgeType
    Explanation string
}
```

### Attack Path Categories

Implement only:

* `public_to_sensitive_data`
* `iam_privilege_escalation`

### Acceptance

* Attack paths can be rendered in JSON, Markdown, PR comments, and HCP outcomes.
* Attack paths can influence policy decisions only when confidence is high or configured.

### Tests

* Golden attack path JSON.
* Redaction tests.
* Sorting tests.

## 22. Tranche 16: Public-to-Sensitive Attack Path v1

### Goal

Detect public entrypoint to sensitive asset paths.

### Detection Logic

Find paths:

```text
internet/public_entrypoint -> workload -> sensitive_asset
```

Sensitive asset includes:

* production RDS/Aurora
* Secrets Manager secret
* KMS key with sensitive relationship
* S3 bucket tagged sensitive or public-access-risky
* OpenSearch/ElastiCache tagged sensitive

Public entrypoint includes:

* internet-facing ALB/NLB/ELB
* API Gateway public route
* CloudFront distribution
* Lambda function URL with public auth
* security group exposing admin ports or workload ports from public CIDRs

### Decision Rules

Default:

* `BLOCK` when public path reaches sensitive production data with high confidence.
* `WARN` when path reaches sensitive data with medium confidence.
* `WARN` when public entrypoint reaches non-sensitive workload.
* `ALLOW` expected public edge with compensating controls and no sensitive downstream path.

### Acceptance

* Public web ALB serving non-sensitive app can be allowed.
* Public admin ALB reaching customer DB blocks.
* Public path with missing sensitive data context warns, not blocks.

### Tests

* Public web allowed fixture.
* Public admin to RDS blocked fixture.
* Public workload to secret blocked fixture.
* Expected public edge downgrade fixture.

## 23. Tranche 17: IAM Attack Path v1

### Goal

Detect high-signal privilege escalation paths.

### Patterns

Start with:

```text
principal -> iam:PassRole -> privileged role -> lambda:UpdateFunctionCode
principal -> iam:PassRole -> privileged role -> ecs:RunTask
principal -> sts:AssumeRole -> admin role
principal -> lambda:UpdateFunctionCode -> function execution role with admin/sensitive access
principal -> ecs:UpdateService -> task role with secrets/data access
```

### IAM Normalization

Implement action matching:

* wildcard actions
* service wildcards
* resource wildcard
* explicit deny awareness where feasible
* basic condition awareness for known safe constraints

Do not attempt a full IAM simulator in v1. If conditions are complex, reduce confidence.

### Decision Rules

* `BLOCK` high-confidence path to administrator access.
* `BLOCK` high-confidence path to sensitive secret/data access in production.
* `WARN` when wildcard/condition ambiguity prevents certainty.

### References

Use known AWS IAM escalation literature and path catalogs, including Datadog `pathfinding.cloud`, as inspiration for taxonomy. Do not vendor third-party data unless license and attribution are reviewed.

### Acceptance

* Terraform plan adding `iam:PassRole` plus function update can block.
* Broad trust to external principal can warn/block depending on context.
* Complex condition policies do not produce false high-confidence blocks.

### Tests

* Table-driven IAM action matcher tests.
* Trust policy parser tests.
* Attack path fixtures for each v1 pattern.
* False-positive fixtures with restrictive conditions.

## 24. Tranche 18: Attack Path CLI

### Goal

Expose attack path analysis independently.

### Commands

```bash
changegate attack-paths --plan tfplan.json
changegate attack-paths --plan tfplan.json --principal aws_iam_role.github_actions
changegate attack-paths --plan tfplan.json --to-sensitive-data
changegate attack-paths --plan tfplan.json --format json
```

### Acceptance

* Security engineers can inspect paths without running enforcement.
* JSON output is stable and references graph path IDs.
* Markdown output is concise and review-ready.

### Tests

* CLI golden tests.
* JSON contract tests.
* Empty-result tests.

## 25. Tranche 19: Policy Integration for Impact and Attack Paths

### Goal

Make impact and attack paths part of deterministic deploy decisions.

### Implementation

* Add built-in rules:
  * `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
  * `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
  * `AWS_IAM_ASSUME_ADMIN_PATH`
  * `AWS_PUBLIC_ADMIN_SERVICE_PATH`
* Link rules to attack paths and graph paths.
* Add config thresholds:

```yaml
attack_paths:
  block:
    - type: public_to_sensitive_data
      min_confidence: high
    - type: iam_privilege_escalation
      min_confidence: high
  warn:
    - type: public_to_sensitive_data
      min_confidence: medium
```

### Acceptance

* Scan reports include attack paths as evidence.
* Decision reasons identify the attack path.
* Waivers can target attack path findings by fingerprint.
* Baselines can suppress existing attack path findings but not worsened paths.

### Tests

* Policy decision tests.
* Waiver application tests.
* Baseline movement tests.

## 26. Tranche 20: HCP Terraform Run Task Protocol

Status: deferred. Do not implement this tranche during the first Review Intelligence development cycle. Resume only after impact statements, PR review, graph v2, cloud context, attack paths, and risk tests are production-ready.

### Goal

Implement the HCP Terraform run task request, callback, and security model.

### Official Protocol Requirements

HCP Terraform run tasks call the configured URL during run lifecycle stages. Post-plan/pre-apply payloads include `plan_json_api_url`. The integration must respond `200 OK`, then callback to `task_result_callback_url` with `running`, `passed`, or `failed`. HCP Terraform supports detailed outcomes with Markdown bodies and severity/status tags.

### Data Model

Add:

```go
type Request struct {
    PayloadVersion int
    Stage          string
    AccessToken    string
    PlanJSONAPIURL string
    CallbackURL    string
    EnforcementLevel string
    RunID          string
    WorkspaceID    string
    WorkspaceName  string
    VCSBranch      string
    VCSPullRequestURL string
}
```

### Security

* Verify `X-TFC-Task-Signature` HMAC SHA-512 when configured.
* Reject unsupported payload version.
* Reject unsupported stages unless configured.
* Do not log `access_token`.
* Enforce max body size.
* Enforce request timeout.

### Acceptance

* Protocol parsing is fully tested.
* HMAC verification is constant-time.
* Invalid signatures return 401/403.
* Valid request can be processed in dry-run mode.

### Tests

* Payload fixture tests.
* HMAC tests.
* Unsupported stage tests.
* Token redaction tests.

## 27. Tranche 21: HCP Terraform Adapter Server

Status: deferred. This tranche depends on Tranche 20 and should remain out of scope until HCP Terraform run task support is explicitly resumed.

### Goal

Ship a self-hosted run task adapter.

### Command

```bash
changegate run-task serve --config changegate-run-task.yaml
```

### Config

```yaml
server:
  listen: ":8080"
  read_timeout: 10s
  write_timeout: 60s

hcp_terraform:
  hmac_secret: env:CHANGEGATE_RUN_TASK_HMAC
  allowed_stages: ["post_plan"]

changegate:
  policy: .changegate.yaml
  mode: default
  context_file: /etc/changegate/aws-context.json
  audit_store: file:///var/lib/changegate/audit
```

### Flow

1. Receive run task request.
2. Verify signature.
3. Return `200 OK`.
4. Send `running` callback.
5. Download plan JSON from `plan_json_api_url` using `access_token`.
6. Run ChangeGate engine.
7. Write audit bundle.
8. Build impact statement.
9. Send `passed` or `failed` callback with detailed outcomes.

### Decision Mapping

```text
ALLOW -> passed
WARN -> passed with warning outcomes, unless config treats warnings as failed
BLOCK -> failed
MANUAL_APPROVAL_REQUIRED -> failed for mandatory task, passed with warning for advisory task only if configured
ERROR -> failed
```

### Acceptance

* Runs in Docker with a mounted config.
* Produces HCP outcomes with severity/status tags.
* Stores audit bundles when configured.
* Fails closed on engine errors for mandatory run tasks.

### Tests

* HTTP handler tests.
* Fake HCP plan download server.
* Fake callback server.
* End-to-end adapter test with fixture payload and plan.

## 28. Tranche 22: HCP Adapter Packaging and Documentation

Status: deferred. This tranche depends on Tranches 20 and 21 and should remain out of scope until the run task adapter is resumed.

### Goal

Make self-hosting the run task adapter easy.

### Deliverables

* Docker image target for `changegate run-task serve`.
* Compose example.
* Kubernetes deployment example.
* Terraform example for HCP run task registration.
* Docs:
  * setup
  * HMAC key configuration
  * network requirements
  * audit storage
  * failure modes
  * advisory vs mandatory behavior
  * private HCP Terraform agent request forwarding considerations

### Acceptance

* User can run adapter locally against a sample payload.
* Docs explain the HCP run task callback lifecycle.
* Adapter image is part of release workflow.

## 29. Tranche 23: Risk Test Manifest

### Goal

Let Terraform module authors write deterministic regression tests for ChangeGate decisions.

### Manifest

```yaml
version: 1
tests:
  - name: public_admin_service_should_block
    plan: fixtures/public-admin-service.json
    config: fixtures/changegate.yaml
    expect:
      decision: block
      findings:
        include:
          - AWS_PUBLIC_ADMIN_SERVICE
      attack_paths:
        include:
          - public_to_sensitive_data

  - name: public_web_alb_should_pass
    plan: fixtures/public-web-alb.json
    expect:
      decision: allow
      findings:
        exclude:
          - AWS_PUBLIC_ADMIN_SERVICE
```

### Assertions

Support:

* decision equals
* finding include/exclude by rule ID
* severity count
* attack path include/exclude
* graph path include
* risk movement values
* waiver applied/not applied
* output snapshot match

### Acceptance

* Manifest parser validates unknown fields.
* Failures are precise and developer-friendly.
* Test runner supports one file or directory discovery.
* Implemented in `internal/risktest`; the CLI command is delivered in Tranche 24.

### Tests

* Parser tests.
* Assertion tests.
* Golden failure output tests.

## 30. Tranche 24: `changegate test` CLI

### Goal

Expose risk tests as an OSS-friendly workflow.

### Commands

```bash
changegate test
changegate test ./changegate-tests
changegate test --format json
changegate test --junit changegate-tests.xml
changegate test --update
```

### Output

```text
PASS public_web_alb_should_pass
FAIL public_admin_service_should_block
  expected decision block, got warn
  missing finding AWS_PUBLIC_ADMIN_SERVICE
```

### Acceptance

* Exit code non-zero on failed tests.
* JSON and JUnit outputs work in CI.
* `--update` updates snapshots only, not expected decisions.
* Implemented as `changegate test` with manifest/directory discovery and optional `--junit` output.

### Tests

* CLI golden tests.
* JUnit output tests.
* Directory discovery tests.

## 31. Tranche 25: Sanitized Fixture Corpus

### Goal

Build a high-quality fixture library that proves the product’s differentiated behavior.

### Fixture Categories

Add fixtures for:

* expected public web ALB allowed
* public admin ALB blocked
* public ALB to ECS to RDS blocked
* Lambda function URL to secret warned/blocked
* PassRole plus Lambda update blocked
* AssumeRole to admin blocked
* stale baseline suppressing unchanged risk
* worsened baseline risk still blocked
* staging waiver accepted
* production waiver rejected
* cloud context downgrades expected public edge
* cloud context upgrades actual public drift

### Fixture Hygiene

* No account IDs unless fake `123456789012`.
* No real ARNs.
* No real domains.
* No real IPs except RFC 5737 examples.
* Minimal plan JSON.
* Each fixture documents what behavior it proves.

### Acceptance

* Fixtures run under `changegate test`.
* Fixtures double as documentation examples.
* Fixture contribution docs are updated.

### Implementation Status

Complete. The sanitized corpus lives in `examples/risk-tests` and covers all tranche categories with fake account ID `123456789012`, minimal hand-written plans, context snapshots, baseline movement, and waiver scoping.

## 32. Tranche 26: Audit Bundle v2

### Goal

Make deploy decisions auditable end-to-end.

### Bundle Additions

Add:

```text
changegate-audit/impact.json
changegate-audit/impact.md
changegate-audit/graph.json
changegate-audit/attack-paths.json
changegate-audit/cloud-context-summary.json
changegate-audit/review-comment.md
changegate-audit/risk-tests.json
changegate-audit/hcp-run-task.json
```

### Acceptance

* Bundle remains deterministic.
* Bundle omits secrets.
* Bundle is usable as HCP adapter evidence.

### Tests

* Golden zip member list.
* Deterministic digest test.
* Redaction test.

### Implementation Status

Complete. `changegate scan --audit-bundle` now writes the v2 bundle members for impact statements, sanitized graph evidence, attack path summaries, cloud-context summaries, sticky review comments, risk-test evidence placeholders, and HCP-run-task-compatible decision evidence.

## 33. Tranche 27: Performance and Scale Hardening

### Goal

Ensure graph v2, cloud context, attack paths, and impact rendering do not make the tool feel heavy.

### Budgets

Initial budgets:

* 1,000 changed resources: scan + graph + impact under 2 seconds on CI runner.
* 10,000 graph nodes with cloud context: path extraction under 5 seconds.
* PR comment render under 250 ms.
* Memory under 512 MB for large fixture.

### Implementation

* Use bounded path search.
* Add max paths and max depth.
* Cache node classifications.
* Avoid all-pairs graph traversal.
* Add context cancellation to cloud collection and run task execution.

### Tests

* Benchmark graph path search.
* Benchmark impact rendering.
* Benchmark attack path detectors.
* CI performance budget tests.

### Implementation Status

Complete. Graph path extraction now avoids per-expansion path copying, blast-radius traversal avoids per-target graph searches, public-to-sensitive attack paths reuse bounded blast-radius traversal, and CI covers scan, memory, graph, impact, PR comment, and attack-path performance budgets/benchmarks.

## 34. Tranche 28: Security Hardening

### Goal

Secure the new networked surfaces and external integrations.

### Checklist

* HCP HMAC signature validation.
* Callback token redaction.
* Request body size limits.
* HTTP timeouts.
* No secrets in logs.
* No command injection in CI review commands.
* Provider API errors are diagnostics.
* PR bot does not run untrusted fork code with write token by default.
* GitHub/GitLab token permissions documented.
* Audit bundles do not contain full cloud inventory by default.

### Tests

* HMAC tampering tests.
* Log redaction tests.
* Malicious Markdown injection tests.
* Oversized request tests.
* Fork PR docs review.

### Implementation Status

Complete for active Review Intelligence surfaces. GitHub/GitLab review clients now enforce bounded request, response, and error bodies, use HTTP timeouts even when clients are constructed manually, and redact provider tokens from API error diagnostics. Review comments escape untrusted Markdown/HTML fragments and neutralize unsafe artifact URLs. The review CLI rejects unsafe artifact URLs and oversized scan reports. GitHub/GitLab docs now call out minimum token permissions and fork-PR safety patterns. HCP HMAC tampering remains deferred with the HCP adapter tranches.

## 35. Tranche 29: Documentation and Examples

### Goal

Make the feature set legible to early adopters.

### Docs to Add or Update

* `docs/review-intelligence.md`
* `docs/security-impact-statement.md`
* `docs/graph.md`
* `docs/attack-paths.md`
* `docs/cloud-context.md`
* `docs/github-actions.md`
* `docs/gitlab-ci.md`
* `docs/terraform-cloud.md`
* `docs/risk-tests.md`
* `docs/audit-compliance.md`
* `docs/security-model.md`
* `README.md`

### Examples

* GitHub PR review workflow.
* GitLab MR review workflow.
* HCP Terraform run task adapter compose file.
* `changegate test` fixture directory.
* AWS read-only permissions template.

### Acceptance

* Docs do not promise hosted SaaS.
* Every command in docs is tested or generated from tests where feasible.
* Examples install ChangeGate instead of assuming it exists.

### Implementation Status

Complete. Added the missing Security Impact Statement guide, refreshed Review Intelligence, attack-path, cloud-context, Terraform Cloud, audit, product, and README documentation to match the implemented CLI, and added a checked-in AWS read-only context policy example generated from `changegate context aws permissions-template`. HCP adapter deployment examples remain explicitly deferred with the HCP adapter tranches rather than documented as available.

## 36. Tranche 30: Release Readiness

### Goal

Ship Review Intelligence as a production-grade update.

### Required Validation

Run:

```bash
gofmt -w ./...
go test ./...
go test -race ./...
go vet ./...
golangci-lint run
govulncheck ./...
scripts/release-build.sh v0.0.0-review-intelligence
```

Also verify:

* GitHub review bot dry-run.
* GitLab review bot dry-run.
* HCP run task adapter end-to-end fake server.
* `changegate test` fixture corpus.
* audit bundle determinism.
* large graph performance budgets.
* Docker image smoke test.

### Release Notes

Release notes must clearly separate:

* stable features
* experimental AWS context collection limitations
* attack path v1 scope
* HCP adapter deployment requirements
* migration notes for output JSON additions

## 37. Production Definition of Done

The Review Intelligence update is production-ready when:

* `changegate impact` is stable and documented.
* `changegate graph path/exposure` works on realistic AWS plans.
* PR comments are sticky, concise, deterministic, and redacted.
* GitHub and GitLab examples are copy-paste usable.
* AWS context collection provides real read-only inventory for the v1 scope.
* Attack path v1 has high-signal fixtures and low false-positive behavior.
* HCP run task adapter verifies signatures, downloads plan JSON, executes ChangeGate, sends outcomes, and stores evidence.
* `changegate test` supports module regression tests with JSON/JUnit output.
* audit bundle v2 captures the full decision trail.
* no new reachable vulnerabilities are reported by `govulncheck`.
* remote CI and Security workflows pass.

## 38. Recommended Implementation Order

The highest ROI implementation order is:

1. Impact model and CLI.
2. PR comment renderer.
3. GitHub review bot.
4. Graph v2 core and graph CLI.
5. Risk movement improvements.
6. Attack path model and public-to-sensitive path.
7. IAM attack path v1.
8. AWS cloud context schema v2.
9. AWS network/edge collector.
10. AWS IAM/data collector.
11. Cloud context graph merge.
12. GitLab review bot.
13. Risk test manifest and CLI.
14. Fixture corpus.
15. Audit bundle v2.
16. Performance and security hardening.
17. Full docs and release readiness.

Deferred until a later cycle:

* HCP run task protocol.
* HCP run task server and packaging.

This order gives users visible value quickly while building toward the enterprise-native HCP adapter and cloud-context intelligence.

## 39. Key External References

* GitHub REST pull request review comment APIs support listing, creating, updating, and deleting review comments: <https://docs.github.com/en/rest/pulls/comments>
* GitHub REST pull request APIs support pull request review operations: <https://docs.github.com/en/rest/reference/pulls>
* GitHub Actions workflow commands support error/warning annotations and Markdown job summaries through workflow command files: <https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions>
* GitLab Merge Request Notes API supports listing, creating, updating, and deleting merge request notes: <https://docs.gitlab.com/api/notes/>
* GitLab Discussions API supports merge request discussions and threaded notes: <https://docs.gitlab.com/api/discussions/>
* HCP Terraform run task setup documentation describes the inbound payload, `plan_json_api_url`, `task_result_callback_url`, bearer callback token, and task result payload: <https://developer.hashicorp.com/terraform/cloud-docs/integrations/run-tasks>
* HCP Terraform run task settings documentation describes how run task results affect run progression based on enforcement level: <https://developer.hashicorp.com/terraform/cloud-docs/workspaces/settings/run-tasks>
