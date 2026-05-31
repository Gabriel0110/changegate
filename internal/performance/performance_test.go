package performance

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/attackpath"
	"github.com/Gabriel0110/changegate/internal/cli"
	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/impact"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
	"github.com/Gabriel0110/changegate/internal/perftest"
	"github.com/Gabriel0110/changegate/internal/review"
	"github.com/Gabriel0110/changegate/internal/rules"
)

func TestSmallPlanPerformanceBudget(t *testing.T) {
	planPath := writePlan(t, 100)
	start := time.Now()
	stdout, stderr, code := runChangeGate("scan", "--plan", planPath, "--format", "json", "--timeout", "5s")
	elapsed := time.Since(start)
	if code != 1 {
		t.Fatalf("exit code = %d, want blocked\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if elapsed > time.Second {
		t.Fatalf("small plan scan took %s, want under 1s", elapsed)
	}
}

func TestLargePlanMemoryBudget(t *testing.T) {
	planPath := writePlan(t, 1000)
	runtime.GC()
	var before runtime.MemStats
	var after runtime.MemStats
	runtime.ReadMemStats(&before)
	stdout, stderr, code := runChangeGate("scan", "--plan", planPath, "--format", "json", "--timeout", "10s", "--max-findings", "25")
	runtime.ReadMemStats(&after)
	if code != 1 {
		t.Fatalf("exit code = %d, want blocked\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if used := after.TotalAlloc - before.TotalAlloc; used > 256*1024*1024 {
		t.Fatalf("large plan allocated %d bytes, want <= 256MiB", used)
	}
}

func TestReviewIntelligencePerformanceBudget(t *testing.T) {
	planPath := writePlan(t, 1000)
	start := time.Now()
	stdout, stderr, code := runChangeGate("impact", "--plan", planPath, "--format", "json", "--timeout", "10s", "--max-findings", "50", "--max-paths", "25")
	elapsed := time.Since(start)
	if code != 1 {
		t.Fatalf("exit code = %d, want blocked\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("1000-resource scan plus impact took %s, want under 2s", elapsed)
	}
}

func TestLargeGraphPathExtractionBudget(t *testing.T) {
	resourceGraph := syntheticReachabilityGraph(10000)
	snapshot := syntheticCloudSnapshotForGraph(10000)
	mergedGraph, diagnostics := graph.MergeContext(resourceGraph, snapshot)
	if len(diagnostics) != 0 {
		t.Fatalf("merge context diagnostics = %#v", diagnostics)
	}
	start := time.Now()
	paths := mergedGraph.Paths("aws_lb.edge", "aws_db_instance.customer_9999", graph.PathOptions{
		MaxDepth:     10005,
		MaxPaths:     1,
		AllowedEdges: []graph.EdgeType{graph.EdgeRoutesTo},
	})
	elapsed := time.Since(start)
	if len(paths) != 1 {
		t.Fatalf("paths = %d, want 1", len(paths))
	}
	if elapsed > 5*time.Second {
		t.Fatalf("10000-node path extraction took %s, want under 5s", elapsed)
	}
}

func TestPRCommentRenderBudget(t *testing.T) {
	statement := benchmarkImpactStatement(t, 1000)
	start := time.Now()
	comment := review.RenderComment(statement, review.CommentOptions{
		MaxFindings:    25,
		MaxGraphPaths:  25,
		MaxAttackPaths: 25,
		MaxBytes:       review.DefaultMaxCommentBytes,
	})
	elapsed := time.Since(start)
	if comment == "" {
		t.Fatal("empty review comment")
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("PR comment render took %s, want under 250ms", elapsed)
	}
}

func BenchmarkSmallScan(b *testing.B) {
	planPath := writePlan(b, 100)
	for b.Loop() {
		_, _, code := runChangeGate("scan", "--plan", planPath, "--format", "json", "--timeout", "5s")
		if code != 1 {
			b.Fatalf("exit code = %d, want blocked", code)
		}
	}
}

func BenchmarkLargeScan(b *testing.B) {
	planPath := writePlan(b, 1000)
	for b.Loop() {
		_, _, code := runChangeGate("scan", "--plan", planPath, "--format", "json", "--timeout", "10s", "--max-findings", "50")
		if code != 1 {
			b.Fatalf("exit code = %d, want blocked", code)
		}
	}
}

func BenchmarkGraphBuild(b *testing.B) {
	plan := perftest.SyntheticPlan(1000)
	for b.Loop() {
		resourceGraph := graph.Build(plan)
		if len(resourceGraph.Nodes) == 0 {
			b.Fatalf("graph has no nodes")
		}
	}
}

func BenchmarkOutputRender(b *testing.B) {
	report := benchmarkReport(b, 250)
	for b.Loop() {
		if _, err := output.RenderJSON(report); err != nil {
			b.Fatalf("render json: %v", err)
		}
	}
}

func BenchmarkCloudContextEnrichment(b *testing.B) {
	plan := perftest.SyntheticPlan(1000)
	snapshot := perftest.CloudSnapshot(plan)
	findings := benchmarkFindings(plan, 1000)
	for b.Loop() {
		enriched, _ := cloudcontext.EnrichFindings(findings, snapshot)
		if len(enriched) != len(findings) {
			b.Fatalf("enriched findings = %d, want %d", len(enriched), len(findings))
		}
	}
}

func BenchmarkCloudContextCacheLoad(b *testing.B) {
	plan := perftest.SyntheticPlan(1000)
	snapshot := perftest.CloudSnapshot(plan)
	var buf bytes.Buffer
	if err := cloudcontext.Write(&buf, snapshot); err != nil {
		b.Fatalf("write snapshot: %v", err)
	}
	path := filepath.Join(b.TempDir(), "aws-context.json")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		b.Fatalf("write cached snapshot: %v", err)
	}
	for b.Loop() {
		loaded, err := cloudcontext.LoadFile(path)
		if err != nil {
			b.Fatalf("load cached snapshot: %v", err)
		}
		if len(loaded.Data.Resources) != len(snapshot.Data.Resources) {
			b.Fatalf("resources = %d, want %d", len(loaded.Data.Resources), len(snapshot.Data.Resources))
		}
	}
}

func BenchmarkGraphPathSearch(b *testing.B) {
	resourceGraph := syntheticReachabilityGraph(10000)
	for b.Loop() {
		paths := resourceGraph.Paths("aws_lb.edge", "aws_db_instance.customer_9999", graph.PathOptions{
			MaxDepth:     10005,
			MaxPaths:     1,
			AllowedEdges: []graph.EdgeType{graph.EdgeRoutesTo},
		})
		if len(paths) != 1 {
			b.Fatalf("paths = %d, want 1", len(paths))
		}
	}
}

func BenchmarkImpactBuild(b *testing.B) {
	report := benchmarkReport(b, 1000)
	for b.Loop() {
		statement, err := impact.Build(report, impact.Options{
			GeneratedAt:        time.Unix(0, 0).UTC(),
			TopFindingsLimit:   50,
			TopGraphPathsLimit: 25,
			AttackPathsLimit:   25,
		})
		if err != nil {
			b.Fatalf("build impact: %v", err)
		}
		if statement.Summary.ResourcesChanged == 0 {
			b.Fatal("impact statement missing resource summary")
		}
	}
}

func BenchmarkPRCommentRender(b *testing.B) {
	statement := benchmarkImpactStatement(b, 1000)
	for b.Loop() {
		comment := review.RenderComment(statement, review.CommentOptions{
			MaxFindings:    25,
			MaxGraphPaths:  25,
			MaxAttackPaths: 25,
			MaxBytes:       review.DefaultMaxCommentBytes,
		})
		if comment == "" {
			b.Fatal("empty review comment")
		}
	}
}

func BenchmarkAttackPathDetectors(b *testing.B) {
	resourceGraph := syntheticAttackPathGraph(1000)
	for b.Loop() {
		paths := attackpath.DetectPublicToSensitive(resourceGraph, attackpath.DetectionOptions{MaxDepth: 12, MaxPaths: 25})
		paths = append(paths, attackpath.DetectIAMPrivilegeEscalation(resourceGraph, attackpath.IAMDetectionOptions{IncludeWarnings: true})...)
		if len(paths) == 0 {
			b.Fatal("expected attack paths")
		}
	}
}

func writePlan(tb testing.TB, resources int) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "tfplan.json")
	if err := os.WriteFile(path, perftest.TerraformPlanJSON(resources), 0o644); err != nil {
		tb.Fatalf("write synthetic plan: %v", err)
	}
	return path
}

func runChangeGate(args ...string) (string, string, int) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := cli.Execute(context.Background(), args, bytes.NewReader(nil), &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func benchmarkReport(tb testing.TB, findings int) output.Report {
	tb.Helper()
	plan := perftest.SyntheticPlan(findings)
	resourceGraph := graph.Build(plan)
	registry, err := rules.DefaultRegistry()
	if err != nil {
		tb.Fatalf("default registry: %v", err)
	}
	outcome := model.EvaluatePolicy(benchmarkFindings(plan, findings), model.DefaultPolicyConfig())
	return output.NewReport("synthetic.tfplan.json", plan, len(resourceGraph.Nodes), len(resourceGraph.Edges), outcome, ruleSummaries(registry), "benchmark report")
}

func benchmarkImpactStatement(tb testing.TB, findings int) impact.Statement {
	tb.Helper()
	statement, err := impact.Build(benchmarkReport(tb, findings), impact.Options{
		GeneratedAt:        time.Unix(0, 0).UTC(),
		TopFindingsLimit:   50,
		TopGraphPathsLimit: 25,
		AttackPathsLimit:   25,
	})
	if err != nil {
		tb.Fatalf("build impact: %v", err)
	}
	return statement
}

func syntheticReachabilityGraph(nodes int) *graph.Graph {
	if nodes < 1 {
		nodes = 1
	}
	resourceGraph := &graph.Graph{
		Nodes: make(map[graph.ResourceID]*graph.Node, nodes+2),
		Edges: make([]graph.Edge, 0, nodes+1),
	}
	edge := graph.ResourceID("aws_lb.edge")
	resourceGraph.Nodes[edge] = &graph.Node{ID: edge, Address: string(edge), Type: "aws_lb", Kind: graph.NodePublicEntrypoint, Name: "edge", Provider: "aws"}
	previous := edge
	for i := 0; i < nodes; i++ {
		id := graph.ResourceID(fmt.Sprintf("aws_db_instance.customer_%04d", i))
		kind := graph.NodeWorkload
		typ := "aws_ecs_service"
		if i == nodes-1 {
			kind = graph.NodeDataStore
			typ = "aws_db_instance"
		}
		resourceGraph.Nodes[id] = &graph.Node{ID: id, Address: string(id), Type: typ, Kind: kind, Name: string(id), Provider: "aws", Changed: true}
		resourceGraph.Edges = append(resourceGraph.Edges, graph.Edge{From: previous, To: id, Type: graph.EdgeRoutesTo, Source: graph.SourcePlan, Confidence: graph.ConfidenceHigh})
		previous = id
	}
	return resourceGraph
}

func syntheticAttackPathGraph(nodes int) *graph.Graph {
	resourceGraph := syntheticReachabilityGraph(nodes)
	internet := graph.ResourceID("internet")
	edge := graph.ResourceID("aws_lb.edge")
	resourceGraph.Nodes[internet] = &graph.Node{ID: internet, Address: string(internet), Type: "internet", Kind: graph.NodeNetworkBoundary, Name: "internet", Synthetic: true}
	resourceGraph.Edges = append(resourceGraph.Edges, graph.Edge{From: internet, To: edge, Type: graph.EdgeHasPublicAccess, Source: graph.SourcePlan, Confidence: graph.ConfidenceHigh})
	principal := graph.ResourceID("aws_iam_role.github_actions")
	policy := graph.ResourceID("aws_iam_policy.deploy")
	role := graph.ResourceID("aws_iam_role.admin_execution")
	resourceGraph.Nodes[principal] = &graph.Node{ID: principal, Address: string(principal), Type: "aws_iam_role", Kind: graph.NodePrincipal, Name: "github_actions", Provider: "aws"}
	resourceGraph.Nodes[policy] = &graph.Node{
		ID:       policy,
		Address:  string(policy),
		Type:     "aws_iam_policy",
		Kind:     graph.NodePolicy,
		Name:     "deploy",
		Provider: "aws",
		Values: map[string]any{
			"policy": `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:UpdateFunctionCode"],"Resource":"*"}]}`,
		},
	}
	resourceGraph.Nodes[role] = &graph.Node{ID: role, Address: string(role), Type: "aws_iam_role", Kind: graph.NodePrincipal, Name: "admin_execution", Provider: "aws", Tags: map[string]string{"privilege": "admin"}}
	resourceGraph.Edges = append(resourceGraph.Edges,
		graph.Edge{From: principal, To: policy, Type: graph.EdgeAttachedTo, Source: graph.SourcePlan, Confidence: graph.ConfidenceHigh},
		graph.Edge{From: principal, To: role, Type: graph.EdgeCanPassRole, Source: graph.SourcePlan, Confidence: graph.ConfidenceHigh},
		graph.Edge{From: principal, To: role, Type: graph.EdgeCanAssume, Source: graph.SourcePlan, Confidence: graph.ConfidenceHigh},
	)
	return resourceGraph
}

func syntheticCloudSnapshotForGraph(nodes int) cloudcontext.Snapshot {
	resources := make(map[string]cloudcontext.Resource, nodes)
	for i := 0; i < nodes; i++ {
		address := fmt.Sprintf("aws_db_instance.customer_%04d", i)
		resources[address] = cloudcontext.Resource{
			TerraformAddress: address,
			AccountID:        "123456789012",
			Type:             "aws_db_instance",
			Region:           "us-east-1",
			Tags:             map[string]string{"env": "prod"},
		}
	}
	return cloudcontext.Snapshot{
		Version:     cloudcontext.Version,
		Provider:    cloudcontext.ProviderAWS,
		GeneratedAt: "2026-05-30T00:00:00Z",
		Account:     cloudcontext.Account{ID: "123456789012"},
		Capabilities: cloudcontext.Capabilities{
			Identity:       true,
			Network:        true,
			SecurityGroups: true,
			IAM:            true,
			S3:             true,
			RDS:            true,
			KMS:            true,
			SecretsManager: true,
			EKS:            true,
		},
		Data: cloudcontext.ResourceSet{Resources: resources},
	}
}

func benchmarkFindings(plan *model.Plan, count int) []model.Finding {
	if count > len(plan.Resources) {
		count = len(plan.Resources)
	}
	findings := make([]model.Finding, 0, count)
	for i := 0; i < count; i++ {
		resource := plan.Resources[i]
		findings = append(findings, model.NormalizeFinding(model.Finding{
			RuleID:            "AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED",
			RuleName:          "Sensitive S3 bucket logging disabled",
			PolicyPack:        "aws-core",
			PolicyPackVersion: "0.1.0",
			Title:             "Sensitive S3 bucket logging disabled",
			ResourceAddress:   resource.Address,
			Provider:          "aws",
			Environment:       "prod",
			Category:          model.RiskCategorySensitiveData,
			Severity:          model.SeverityHigh,
			Confidence:        model.ConfidenceHigh,
			Evidence: []model.Evidence{{
				Type:     "attribute",
				Resource: resource.Address,
				Path:     "logging",
				Message:  "sensitive bucket has no logging resource",
			}},
			Remediation: model.Remediation{Summary: "Enable access logging."},
		}))
	}
	return findings
}

func ruleSummaries(registry *rules.Registry) map[string]output.RuleSummary {
	out := make(map[string]output.RuleSummary)
	for _, rule := range registry.Rules() {
		meta := rule.Metadata()
		out[meta.ID] = output.RuleSummary{
			ID:          meta.ID,
			Name:        meta.Title,
			Description: meta.Description,
			Category:    meta.Category,
			Severity:    meta.Severity,
			Confidence:  meta.Confidence,
			Help:        meta.Documentation.Rationale,
			Remediation: meta.Documentation.Remediation,
			References:  meta.Documentation.References,
		}
	}
	return out
}
