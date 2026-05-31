package attackpath

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestRenderJSONGolden(t *testing.T) {
	t.Parallel()
	got, err := RenderJSON([]AttackPath{fixturePublicPath(), fixtureIAMPath()})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "attack-paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantText := strings.ReplaceAll(string(want), "\r\n", "\n")
	gotText := strings.ReplaceAll(string(got)+"\n", "\r\n", "\n")
	if gotText != wantText {
		t.Fatalf("unexpected JSON\nwant:\n%s\ngot:\n%s\n", wantText, gotText)
	}
	var result Result
	if err := json.Unmarshal(got, &result); err != nil {
		t.Fatalf("rendered JSON does not unmarshal: %v", err)
	}
	if result.Version != ResultVersion {
		t.Fatalf("version = %d, want %d", result.Version, ResultVersion)
	}
}

func TestNormalizeRedactsEvidence(t *testing.T) {
	t.Parallel()
	paths := Normalize([]AttackPath{{
		Type:       TypeIAMPrivilegeEscalation,
		Title:      "Secret evidence",
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		Decision:   model.DecisionBlock,
		Evidence: []model.Evidence{{
			Type:      "iam_policy",
			Resource:  "aws_iam_policy.deploy",
			Path:      "policy",
			Value:     "super-secret-token",
			Sensitive: true,
			Message:   "policy contains sensitive value",
		}},
	}})
	if len(paths) != 1 || len(paths[0].Evidence) != 1 {
		t.Fatalf("unexpected normalized evidence: %#v", paths)
	}
	if paths[0].Evidence[0].Value != "(sensitive)" {
		t.Fatalf("evidence value was not redacted: %#v", paths[0].Evidence[0].Value)
	}
	if !paths[0].Evidence[0].Sensitive {
		t.Fatal("redacted evidence should retain sensitive marker")
	}
}

func TestNormalizeSortsByRisk(t *testing.T) {
	t.Parallel()
	paths := Normalize([]AttackPath{
		{
			ID:         "low",
			Type:       TypePublicToSensitiveData,
			Title:      "Low",
			Severity:   model.SeverityMedium,
			Confidence: model.ConfidenceMedium,
			Decision:   model.DecisionWarn,
			Target:     "aws_db_instance.customer",
		},
		{
			ID:         "high",
			Type:       TypeIAMPrivilegeEscalation,
			Title:      "High",
			Severity:   model.SeverityCritical,
			Confidence: model.ConfidenceHigh,
			Decision:   model.DecisionBlock,
			Target:     "aws_iam_role.admin",
		},
	})
	if paths[0].ID != "high" {
		t.Fatalf("first path = %q, want high", paths[0].ID)
	}
}

func TestRenderMarkdownEmpty(t *testing.T) {
	t.Parallel()
	got := RenderMarkdown(nil)
	if got != "# Attack Paths\n\nNo attack paths detected.\n" {
		t.Fatalf("unexpected empty markdown: %q", got)
	}
}

func fixturePublicPath() AttackPath {
	return AttackPath{
		ID:         "attack-path-public-admin",
		Type:       TypePublicToSensitiveData,
		Title:      "Public admin service reaches customer database",
		Severity:   model.SeverityCritical,
		Confidence: model.ConfidenceHigh,
		Decision:   model.DecisionBlock,
		Entrypoint: "aws_lb.admin",
		Target:     "aws_db_instance.customer",
		Steps: []Step{
			{
				From:        "internet",
				To:          "aws_lb.admin",
				Action:      "public HTTP ingress",
				EdgeType:    graph.EdgeRoutesTo,
				Explanation: "internet-facing load balancer accepts public traffic",
			},
			{
				From:        "aws_lb.admin",
				To:          "aws_ecs_service.admin",
				Action:      "listener forwards",
				EdgeType:    graph.EdgeRoutesTo,
				Explanation: "load balancer routes to admin workload",
			},
			{
				From:        "aws_ecs_service.admin",
				To:          "aws_db_instance.customer",
				Action:      "network reachability",
				EdgeType:    graph.EdgeRoutesTo,
				Explanation: "admin workload can reach sensitive customer datastore",
			},
		},
		Evidence: []model.Evidence{{
			Type:     "graph_path",
			Resource: "aws_db_instance.customer",
			Path:     "internet->aws_lb.admin->aws_ecs_service.admin->aws_db_instance.customer",
			Value:    []string{"internet", "aws_lb.admin", "aws_ecs_service.admin", "aws_db_instance.customer"},
			Message:  "public entrypoint reaches sensitive datastore",
		}},
		Mitigations: []string{
			"Make the load balancer internal or restrict ingress to approved CIDRs.",
			"Separate the admin workload from customer data network paths.",
		},
		References: []string{"https://changegate.dev/docs/attack-paths"},
	}
}

func fixtureIAMPath() AttackPath {
	return AttackPath{
		ID:         "attack-path-passrole-lambda",
		Type:       TypeIAMPrivilegeEscalation,
		Title:      "Deploy principal can update Lambda with privileged role",
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		Decision:   model.DecisionBlock,
		Principal:  "aws_iam_role.github_actions",
		Target:     "aws_iam_role.admin_execution",
		Steps: []Step{
			{
				From:        "aws_iam_role.github_actions",
				To:          "aws_iam_role.admin_execution",
				Action:      "iam:PassRole",
				EdgeType:    graph.EdgeCanPassRole,
				Explanation: "principal can pass an administrative execution role",
			},
			{
				From:        "aws_iam_role.github_actions",
				To:          "aws_lambda_function.worker",
				Action:      "lambda:UpdateFunctionCode",
				EdgeType:    graph.EdgeGrantsPermission,
				Explanation: "principal can update executable code",
			},
		},
		Mitigations: []string{"Scope iam:PassRole to non-admin execution roles."},
	}
}
