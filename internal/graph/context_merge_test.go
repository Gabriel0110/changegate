package graph

import (
	"encoding/json"
	"slices"
	"sort"
	"testing"

	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestMergeContextMatchesTerraformAddress(t *testing.T) {
	t.Parallel()
	public := true
	plan := &model.Plan{
		Resources: []model.Resource{{
			Address: "aws_lb.admin",
			Type:    "aws_lb",
			Name:    "admin",
			Values: map[string]any{
				"scheme": "internal",
			},
		}},
	}
	planGraph := Build(plan)
	merged, diagnostics := MergeContext(planGraph, cloudcontext.Snapshot{
		Version:  cloudcontext.Version,
		Provider: cloudcontext.ProviderAWS,
		Edge: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"aws_lb.admin": {
				TerraformAddress: "aws_lb.admin",
				ARN:              "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/admin/abc",
				Type:             "aws_lb",
				Region:           "us-east-1",
				Public:           &public,
				Tags:             map[string]string{"env": "prod"},
			},
		}},
	})

	node := merged.Nodes["aws_lb.admin"]
	if node == nil {
		t.Fatal("merged graph missing aws_lb.admin")
	}
	if _, ok := merged.Nodes["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/admin/abc"]; ok {
		t.Fatal("context created duplicate load balancer node instead of matching Terraform address")
	}
	if got := node.Values["arn"]; got != "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/admin/abc" {
		t.Fatalf("expected context ARN on node, got %#v", got)
	}
	if !hasDiagnostic(diagnostics, DiagnosticCloudPublicConflict) {
		t.Fatalf("expected public conflict diagnostic, got %#v", diagnostics)
	}
	if !hasEdgeWithSource(merged, InternetNodeID, "aws_lb.admin", EdgeHasPublicAccess, SourceCloudContext) {
		t.Fatalf("expected cloud-context public edge, got %#v", merged.Edges)
	}
}

func TestMergeContextMatchesARNAndID(t *testing.T) {
	t.Parallel()
	plan := &model.Plan{
		Resources: []model.Resource{
			{
				Address: "aws_ecs_service.admin",
				Type:    "aws_ecs_service",
				Name:    "admin",
				Values: map[string]any{
					"id": "arn:aws:ecs:us-east-1:123456789012:service/cluster/admin",
				},
			},
			{
				Address: "aws_db_instance.customer",
				Type:    "aws_db_instance",
				Name:    "customer",
				Values: map[string]any{
					"id": "customer-prod",
				},
			},
		},
	}
	planGraph := Build(plan)
	merged, diagnostics := MergeContext(planGraph, cloudcontext.Snapshot{
		Version:  cloudcontext.Version,
		Provider: cloudcontext.ProviderAWS,
		Compute: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"live-service": {
				ARN:  "arn:aws:ecs:us-east-1:123456789012:service/cluster/admin",
				Type: "aws_ecs_service",
			},
		}},
		Data: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"live-db": {
				ID:            "customer-prod",
				Type:          "aws_db_instance",
				SensitiveData: true,
			},
		}},
		Relationships: []cloudcontext.Relationship{{
			From:       "arn:aws:ecs:us-east-1:123456789012:service/cluster/admin",
			To:         "customer-prod",
			Type:       "network_reaches",
			Confidence: "high",
		}},
	})

	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %#v", diagnostics)
	}
	if !hasEdgeWithSource(merged, "aws_ecs_service.admin", "aws_db_instance.customer", EdgeRoutesTo, SourceCloudContext) {
		t.Fatalf("expected ARN/ID matched context edge, got %#v", merged.Edges)
	}
	if _, ok := merged.Nodes["live-service"]; ok {
		t.Fatal("context created duplicate service node instead of matching ARN")
	}
}

func TestMergeContextPrefersARNOverConflictingFriendlyAlias(t *testing.T) {
	t.Parallel()

	merged, diagnostics := MergeContext(&Graph{Nodes: map[ResourceID]*Node{}}, cloudcontext.Snapshot{
		Version:  cloudcontext.Version,
		Provider: cloudcontext.ProviderAWS,
		Data: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"arn:aws:rds:us-east-1:123456789012:db:customer": {
				ARN:           "arn:aws:rds:us-east-1:123456789012:db:customer",
				ID:            "customer",
				Type:          "aws_db_instance",
				Tags:          map[string]string{"Name": "customer-db"},
				SensitiveData: true,
			},
			"arn:aws:secretsmanager:us-east-1:123456789012:secret:customer-db": {
				ARN:           "arn:aws:secretsmanager:us-east-1:123456789012:secret:customer-db",
				ID:            "customer-db",
				Type:          "aws_secretsmanager_secret",
				SensitiveData: true,
			},
		}},
		Relationships: []cloudcontext.Relationship{{
			From: "arn:aws:secretsmanager:us-east-1:123456789012:secret:customer-db",
			To:   "arn:aws:rds:us-east-1:123456789012:db:customer",
			Type: "protects",
		}},
	})

	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %#v", diagnostics)
	}
	if merged.Nodes["arn:aws:secretsmanager:us-east-1:123456789012:secret:customer-db"] == nil {
		t.Fatalf("secret node was collapsed into conflicting friendly alias; nodes=%v", sortedNodeIDsForTest(merged))
	}
	if !hasEdgeWithSource(merged, "arn:aws:secretsmanager:us-east-1:123456789012:secret:customer-db", "arn:aws:rds:us-east-1:123456789012:db:customer", EdgeProtects, SourceCloudContext) {
		t.Fatalf("expected secret-to-database edge, got %#v", merged.Edges)
	}
}

func TestMergeContextRecordsBothSourcesOnDuplicateEdge(t *testing.T) {
	t.Parallel()
	planGraph := &Graph{Nodes: map[ResourceID]*Node{
		"aws_lb.admin":          {ID: "aws_lb.admin", Address: "aws_lb.admin", Type: "aws_lb", Kind: NodePublicEntrypoint, Name: "admin"},
		"aws_ecs_service.admin": {ID: "aws_ecs_service.admin", Address: "aws_ecs_service.admin", Type: "aws_ecs_service", Kind: NodeWorkload, Name: "admin"},
	}}
	planGraph.addEdgeWithProvenance("aws_lb.admin", "aws_ecs_service.admin", EdgeRoutesTo, SourcePlan, ConfidenceMedium, nil, nil)

	merged, diagnostics := MergeContext(planGraph, cloudcontext.Snapshot{
		Version:  cloudcontext.Version,
		Provider: cloudcontext.ProviderAWS,
		Relationships: []cloudcontext.Relationship{{
			From:       "aws_lb.admin",
			To:         "aws_ecs_service.admin",
			Type:       "routes_to",
			Confidence: "high",
		}},
	})

	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %#v", diagnostics)
	}
	for _, edge := range merged.Edges {
		if edge.From == "aws_lb.admin" && edge.To == "aws_ecs_service.admin" && edge.Type == EdgeRoutesTo {
			if edge.Source != SourceMixed {
				t.Fatalf("source = %q, want %q", edge.Source, SourceMixed)
			}
			if edge.Confidence != ConfidenceHigh {
				t.Fatalf("confidence = %q, want high", edge.Confidence)
			}
			if edge.Metadata["sources"] != "cloud_context,plan" {
				t.Fatalf("sources metadata = %q, want cloud_context,plan", edge.Metadata["sources"])
			}
			return
		}
	}
	t.Fatalf("expected duplicate edge to merge, got %#v", merged.Edges)
}

func TestMergeContextConflictDiagnostics(t *testing.T) {
	t.Parallel()
	public := true
	planGraph := Build(&model.Plan{Resources: []model.Resource{{
		Address: "aws_ecs_service.admin",
		Type:    "aws_ecs_service",
		Name:    "admin",
	}}})

	merged, diagnostics := MergeContext(planGraph, cloudcontext.Snapshot{
		Version:  cloudcontext.Version,
		Provider: cloudcontext.ProviderAWS,
		Compute: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"aws_ecs_service.admin": {
				TerraformAddress: "aws_ecs_service.admin",
				Type:             "aws_ecs_service",
				Public:           &public,
			},
			"eni-123": {
				ID:   "eni-123",
				Type: "aws_network_interface",
			},
		}},
		Relationships: []cloudcontext.Relationship{{
			From: "eni-123",
			To:   "aws_ecs_service.admin",
			Type: "attached_to",
		}},
	})

	for _, code := range []string{
		DiagnosticCloudAttachmentConflict,
		DiagnosticCloudPublicConflict,
		DiagnosticCloudUnmanagedRelationship,
	} {
		if !hasDiagnostic(diagnostics, code) {
			t.Fatalf("expected diagnostic %s, got %#v", code, diagnostics)
		}
	}
	if !hasEdgeWithSource(merged, "eni-123", "aws_ecs_service.admin", EdgeAttachedTo, SourceCloudContext) {
		t.Fatalf("expected attachment edge, got %#v", merged.Edges)
	}
}

func TestMergeContextDoesNotWarnForUnrelatedLiveOnlyInventory(t *testing.T) {
	t.Parallel()
	public := true
	planGraph := Build(&model.Plan{Resources: []model.Resource{{
		Address: "aws_lb.admin",
		Type:    "aws_lb",
		Name:    "admin",
	}}})

	merged, diagnostics := MergeContext(planGraph, cloudcontext.Snapshot{
		Version:  cloudcontext.Version,
		Provider: cloudcontext.ProviderAWS,
		Network: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"vpc-live": {
				ID:   "vpc-live",
				Type: "aws_vpc",
			},
			"sg-live": {
				ID:     "sg-live",
				Type:   "aws_security_group",
				Public: &public,
			},
		}},
		Relationships: []cloudcontext.Relationship{{
			From: "vpc-live",
			To:   "sg-live",
			Type: "contains",
		}},
	})

	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics for unrelated live-only inventory, got %#v", diagnostics)
	}
	if !hasEdgeWithSource(merged, "vpc-live", "sg-live", EdgeContainedIn, SourceCloudContext) {
		t.Fatalf("expected live-only relationship to remain in graph, got %#v", merged.Edges)
	}
	if !hasEdgeWithSource(merged, InternetNodeID, "sg-live", EdgeHasPublicAccess, SourceCloudContext) {
		t.Fatalf("expected live-only public edge to remain in graph, got %#v", merged.Edges)
	}
}

func TestMergeContextDeterministic(t *testing.T) {
	t.Parallel()
	public := true
	planGraph := Build(&model.Plan{Resources: []model.Resource{{
		Address: "aws_lb.admin",
		Type:    "aws_lb",
		Name:    "admin",
	}}})
	snapshot := cloudcontext.Snapshot{
		Version:  cloudcontext.Version,
		Provider: cloudcontext.ProviderAWS,
		Edge: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"aws_lb.admin": {
				TerraformAddress: "aws_lb.admin",
				Type:             "aws_lb",
				Public:           &public,
			},
		}},
		Relationships: []cloudcontext.Relationship{{
			From:       "aws_lb.admin",
			To:         "aws_ecs_service.admin",
			Type:       "routes_to",
			Confidence: "high",
		}},
	}

	leftGraph, leftDiagnostics := MergeContext(planGraph, snapshot)
	rightGraph, rightDiagnostics := MergeContext(planGraph, snapshot)
	leftJSON, err := json.Marshal(struct {
		Graph       *Graph             `json:"graph"`
		Diagnostics []model.Diagnostic `json:"diagnostics"`
	}{Graph: leftGraph, Diagnostics: leftDiagnostics})
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := json.Marshal(struct {
		Graph       *Graph             `json:"graph"`
		Diagnostics []model.Diagnostic `json:"diagnostics"`
	}{Graph: rightGraph, Diagnostics: rightDiagnostics})
	if err != nil {
		t.Fatal(err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("merge is not deterministic\nleft:  %s\nright: %s", leftJSON, rightJSON)
	}
}

func hasDiagnostic(diagnostics []model.Diagnostic, code string) bool {
	return slices.ContainsFunc(diagnostics, func(diagnostic model.Diagnostic) bool {
		return diagnostic.Code == code
	})
}

func hasEdgeWithSource(g *Graph, from ResourceID, to ResourceID, edgeType EdgeType, source EdgeSource) bool {
	return slices.ContainsFunc(g.Edges, func(edge Edge) bool {
		return edge.From == from && edge.To == to && edge.Type == edgeType && edge.Source == source
	})
}

func sortedNodeIDsForTest(g *Graph) []ResourceID {
	ids := make([]ResourceID, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.SliceStable(ids, func(i int, j int) bool { return ids[i] < ids[j] })
	return ids
}
