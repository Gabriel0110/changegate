package performance

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/cli"
	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
	"github.com/Gabriel0110/changegate/internal/perftest"
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
		if len(loaded.Resources) != len(snapshot.Resources) {
			b.Fatalf("resources = %d, want %d", len(loaded.Resources), len(snapshot.Resources))
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
