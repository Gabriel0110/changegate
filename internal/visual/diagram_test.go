package visual

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/attackpath"
	graphpkg "github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestRenderDOT(t *testing.T) {
	diagram := sampleDiagram()
	got := string(RenderDOT(diagram))
	for _, want := range []string{
		"digraph ChangeGate",
		"label=\"ChangeGate Test\"",
		"fillcolor=\"#eff6ff\"",
		"routes to",
		"->",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("DOT missing %q:\n%s", want, got)
		}
	}
}

func TestRenderMermaid(t *testing.T) {
	diagram := sampleDiagram()
	got := string(RenderMermaid(diagram))
	for _, want := range []string{
		"flowchart LR",
		"%% ChangeGate Test",
		"[\"admin<br/>public_entrypoint\"]",
		"-->|\"routes to\"|",
		"classDef public",
		" public",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Mermaid missing %q:\n%s", want, got)
		}
	}
}

func TestRenderHTML(t *testing.T) {
	diagram := sampleDiagram()
	got := string(RenderHTML(diagram))
	for _, want := range []string{
		"<!doctype html>",
		"ChangeGate Test",
		"CHANGEGATE_DIAGRAM",
		"data-role=\"public\"",
		"Filter resources",
		"aws_lb.admin",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("HTML missing %q:\n%s", want, got)
		}
	}
}

func TestRenderAttackPathsFromGoldenJSON(t *testing.T) {
	var result attackpath.Result
	readJSON(t, filepath.Join("..", "attackpath", "testdata", "golden", "attack-paths.json"), &result)
	diagram := NewAttackPathDiagram(result.Paths)
	if len(diagram.Nodes) == 0 || len(diagram.Edges) == 0 {
		t.Fatalf("expected attack path diagram nodes and edges, got %d nodes %d edges", len(diagram.Nodes), len(diagram.Edges))
	}
	dot := string(RenderDOT(diagram))
	mermaid := string(RenderMermaid(diagram))
	for _, output := range []string{dot, mermaid} {
		if !strings.Contains(output, "github_actions") {
			t.Fatalf("expected rendered output to include release validation principal:\n%s", output)
		}
		if !strings.Contains(output, "admin_execution") {
			t.Fatalf("expected rendered output to include release validation target:\n%s", output)
		}
	}
}

func TestRenderGraphPathFromInlinePath(t *testing.T) {
	result := struct {
		Paths []graphpkg.Path `json:"paths"`
	}{
		Paths: []graphpkg.Path{{
			Nodes: []graphpkg.ResourceID{"aws_lb.admin", "aws_ecs_service.admin", "aws_db_instance.customer"},
			Edges: []graphpkg.Edge{
				{From: "aws_lb.admin", To: "aws_ecs_service.admin", Type: graphpkg.EdgeRoutesTo, Source: graphpkg.SourcePlan, Confidence: graphpkg.ConfidenceHigh},
				{From: "aws_ecs_service.admin", To: "aws_db_instance.customer", Type: graphpkg.EdgeCanReadData, Source: graphpkg.SourcePlan, Confidence: graphpkg.ConfidenceHigh},
			},
		}},
	}
	g := graphFromPaths(result.Paths)
	diagram := NewGraphPathDiagram(g, "aws_lb.admin", "aws_db_instance.customer", result.Paths)
	if len(diagram.Nodes) == 0 || len(diagram.Edges) == 0 {
		t.Fatalf("expected graph path diagram nodes and edges, got %d nodes %d edges", len(diagram.Nodes), len(diagram.Edges))
	}
	dot := string(RenderDOT(diagram))
	mermaid := string(RenderMermaid(diagram))
	for _, output := range []string{dot, mermaid} {
		if !strings.Contains(output, "admin") {
			t.Fatalf("expected rendered output to include path source labels:\n%s", output)
		}
		if !strings.Contains(output, "customer") {
			t.Fatalf("expected rendered output to include path target labels:\n%s", output)
		}
	}
}

func sampleDiagram() Diagram {
	return Diagram{
		Title: "ChangeGate Test",
		Nodes: []Node{
			{ID: "aws_lb.admin", Label: "admin", Kind: "public_entrypoint", Role: RolePublic},
			{ID: "aws_ecs_service.admin", Label: "admin service", Kind: "workload", Role: RoleWorkload},
		},
		Edges: []Edge{
			{From: "aws_lb.admin", To: "aws_ecs_service.admin", Label: "routes to", Role: RolePath},
		},
	}
}

func graphFromPaths(paths []graphpkg.Path) *graphpkg.Graph {
	g := &graphpkg.Graph{Nodes: make(map[graphpkg.ResourceID]*graphpkg.Node)}
	for _, path := range paths {
		for _, id := range path.Nodes {
			if g.Nodes[id] == nil {
				g.Nodes[id] = &graphpkg.Node{
					ID:      id,
					Address: string(id),
					Name:    string(id),
					Kind:    graphpkg.NodeUnknown,
				}
			}
		}
		g.Edges = append(g.Edges, path.Edges...)
	}
	if node := g.Nodes["aws_lb.admin"]; node != nil {
		node.Kind = graphpkg.NodePublicEntrypoint
	}
	if node := g.Nodes["aws_ecs_service.admin"]; node != nil {
		node.Kind = graphpkg.NodeWorkload
	}
	if node := g.Nodes["aws_db_instance.customer"]; node != nil {
		node.Kind = graphpkg.NodeDataStore
	}
	return g
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func TestRoleForDecision(t *testing.T) {
	if got := roleForDecision(model.DecisionBlock); got != RoleBlock {
		t.Fatalf("block role = %s", got)
	}
}
