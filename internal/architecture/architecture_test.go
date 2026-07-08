package architecture

import (
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/graph"
)

func TestBuildViewFiltersArchitectureViews(t *testing.T) {
	t.Parallel()

	snapshot := testSnapshot()
	g, diagnostics := BuildGraph(snapshot)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}

	tests := []struct {
		name      string
		opts      Options
		wantNode  graph.ResourceID
		avoidNode graph.ResourceID
	}{
		{
			name:     "public exposure includes downstream datastore",
			opts:     Options{View: ViewPublicExposure, MaxDepth: 5, MaxNodes: 100},
			wantNode: "arn:aws:rds:us-east-1:123456789012:db:customer",
		},
		{
			name:      "iam avoids rds by default",
			opts:      Options{View: ViewIAM, MaxDepth: 1, MaxNodes: 100},
			wantNode:  "arn:aws:iam::123456789012:role/app",
			avoidNode: "arn:aws:rds:us-east-1:123456789012:db:customer",
		},
		{
			name:      "iam avoids policy action internals",
			opts:      Options{View: ViewIAM, MaxDepth: 2, MaxNodes: 100},
			wantNode:  "arn:aws:iam::123456789012:policy/app",
			avoidNode: "action:s3:GetObject",
		},
		{
			name:     "resource resolves by arn",
			opts:     Options{View: ViewResource, Resource: "arn:aws:lambda:us-east-1:123456789012:function:api", MaxDepth: 1, MaxNodes: 100},
			wantNode: "arn:aws:lambda:us-east-1:123456789012:function:api",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			view, truncated, err := BuildView(g, tt.opts)
			if err != nil {
				t.Fatalf("BuildView returned error: %v", err)
			}
			if truncated {
				t.Fatalf("view was unexpectedly truncated")
			}
			if view.Nodes[tt.wantNode] == nil {
				t.Fatalf("view missing %s; nodes=%v", tt.wantNode, sortedNodeIDs(view))
			}
			if tt.avoidNode != "" && view.Nodes[tt.avoidNode] != nil {
				t.Fatalf("view unexpectedly included %s", tt.avoidNode)
			}
		})
	}
}

func TestAccountViewExcludesIAMPolicyInternals(t *testing.T) {
	t.Parallel()

	g, diagnostics := BuildGraph(testSnapshot())
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	view, truncated, err := BuildView(g, Options{View: ViewAccount, MaxNodes: 100})
	if err != nil {
		t.Fatalf("BuildView returned error: %v", err)
	}
	if truncated {
		t.Fatalf("view was unexpectedly truncated")
	}
	for _, unwanted := range []graph.ResourceID{
		"arn:aws:iam::123456789012:role/app",
		"arn:aws:iam::123456789012:policy/app",
		"action:s3:GetObject",
		"*",
	} {
		if view.Nodes[unwanted] != nil {
			t.Fatalf("account architecture view included non-architecture node %s", unwanted)
		}
	}
	for _, wanted := range []graph.ResourceID{
		"aws-account:123456789012",
		"aws-region:us-east-1",
		"arn:aws:lambda:us-east-1:123456789012:function:api",
		"arn:aws:rds:us-east-1:123456789012:db:customer",
	} {
		if view.Nodes[wanted] == nil {
			t.Fatalf("account architecture view missing %s", wanted)
		}
	}
}

func TestBuildViewTruncatesDeterministically(t *testing.T) {
	t.Parallel()

	g, _ := BuildGraph(testSnapshot())
	view, truncated, err := BuildView(g, Options{View: ViewAccount, MaxNodes: 3})
	if err != nil {
		t.Fatalf("BuildView returned error: %v", err)
	}
	if !truncated {
		t.Fatalf("expected truncation")
	}
	if len(view.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(view.Nodes))
	}
}

func TestMapDataAccountGroupContainsTopLevelContainers(t *testing.T) {
	t.Parallel()

	snapshot := testSnapshot()
	g, diagnostics := BuildGraph(snapshot)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	view, truncated, err := BuildView(g, Options{View: ViewAccount, MaxNodes: 100})
	if err != nil {
		t.Fatalf("BuildView returned error: %v", err)
	}
	summary := Summarize(snapshot, view, ViewAccount, nil, truncated)
	data := buildMapData(snapshot, view, summary)
	var account *mapGroup
	for index := range data.Groups {
		if data.Groups[index].ID == "aws-account:123456789012" {
			account = &data.Groups[index]
			break
		}
	}
	if account == nil {
		t.Fatalf("account group not found")
	}
	if len(account.Children) == 0 {
		t.Fatalf("account group has no children")
	}
	if !containsString(account.Children, "aws-region:us-east-1") {
		t.Fatalf("account children = %v, want aws-region:us-east-1", account.Children)
	}
}

func TestMapDataAddsReadableServiceIdentity(t *testing.T) {
	t.Parallel()

	snapshot := testSnapshot()
	g, diagnostics := BuildGraph(snapshot)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	view, truncated, err := BuildView(g, Options{View: ViewAccount, MaxNodes: 100})
	if err != nil {
		t.Fatalf("BuildView returned error: %v", err)
	}
	summary := Summarize(snapshot, view, ViewAccount, nil, truncated)
	data := buildMapData(snapshot, view, summary)

	nodes := make(map[string]mapNode, len(data.Nodes))
	for _, node := range data.Nodes {
		nodes[node.ID] = node
	}
	lambda := nodes["arn:aws:lambda:us-east-1:123456789012:function:api"]
	if lambda.Service != "Lambda" {
		t.Fatalf("lambda service = %q, want Lambda", lambda.Service)
	}
	rds := nodes["arn:aws:rds:us-east-1:123456789012:db:customer"]
	if rds.Service != "RDS" {
		t.Fatalf("rds service = %q, want RDS", rds.Service)
	}
	if got := serviceLabelForType("aws_iam_role"); got != "IAM Role" {
		t.Fatalf("iam role service = %q, want IAM Role", got)
	}
}

func TestMapDataKeepsSparseVPCCompact(t *testing.T) {
	t.Parallel()

	snapshot := sparseVPCSnapshot()
	g, diagnostics := BuildGraph(snapshot)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	view, truncated, err := BuildView(g, Options{View: ViewAccount, MaxNodes: 100})
	if err != nil {
		t.Fatalf("BuildView returned error: %v", err)
	}
	summary := Summarize(snapshot, view, ViewAccount, nil, truncated)
	data := buildMapData(snapshot, view, summary)

	groupByID := make(map[string]mapGroup, len(data.Groups))
	for _, group := range data.Groups {
		groupByID[group.ID] = group
		if strings.HasPrefix(group.ID, "subnet-") {
			t.Fatalf("sparse VPC rendered empty subnet container %s", group.ID)
		}
	}
	vpc := groupByID["vpc-0b744527525aa41a9"]
	if vpc.Width > 760 {
		t.Fatalf("sparse VPC width = %.1f, want compact width", vpc.Width)
	}
	if vpc.Height > 320 {
		t.Fatalf("sparse VPC height = %.1f, want compact height", vpc.Height)
	}
	vpcResources := groupByID["vpc-services-vpc-0b744527525aa41a9"]
	if vpcResources.Width > 640 {
		t.Fatalf("VPC resources width = %.1f, want sparse section width", vpcResources.Width)
	}
	if got := len(vpcResources.Children); got != 2 {
		t.Fatalf("VPC resources children = %d, want 2", got)
	}
}

func TestMapDataSizesLongIdentifierCards(t *testing.T) {
	t.Parallel()

	snapshot := sparseVPCSnapshot()
	g, diagnostics := BuildGraph(snapshot)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	view, truncated, err := BuildView(g, Options{View: ViewAccount, MaxNodes: 100})
	if err != nil {
		t.Fatalf("BuildView returned error: %v", err)
	}
	summary := Summarize(snapshot, view, ViewAccount, nil, truncated)
	data := buildMapData(snapshot, view, summary)

	nodes := make(map[string]mapNode, len(data.Nodes))
	for _, node := range data.Nodes {
		nodes[node.ID] = node
	}
	routeTable := nodes["rtb-0c673ec5e49e9a7aa"]
	if routeTable.Width <= mapResourceMinWidth {
		t.Fatalf("long route table card width = %.1f, want larger than minimum %.1f", routeTable.Width, mapResourceMinWidth)
	}
	if routeTable.Width > mapResourceMaxWidth {
		t.Fatalf("long route table card width = %.1f, want at most %.1f", routeTable.Width, mapResourceMaxWidth)
	}
	global := groupByID(data.Groups, "global-services")
	if global.ID == "" {
		t.Fatalf("global services group not found")
	}
	if global.Parent != "aws-account:927120871591" {
		t.Fatalf("global services parent = %q, want account group", global.Parent)
	}
	if global.Width > 360 {
		t.Fatalf("single global service width = %.1f, want compact one-column section", global.Width)
	}
	if wrapper := groupByID(data.Groups, "global"); wrapper.ID != "" {
		t.Fatalf("redundant global wrapper rendered: %#v", wrapper)
	}
}

func groupByID(groups []mapGroup, id string) mapGroup {
	for _, group := range groups {
		if group.ID == id {
			return group
		}
	}
	return mapGroup{}
}

func testSnapshot() cloudcontext.Snapshot {
	public := true
	return cloudcontext.Snapshot{
		Version:     cloudcontext.Version,
		Provider:    cloudcontext.ProviderAWS,
		GeneratedAt: "2026-07-07T00:00:00Z",
		Account:     cloudcontext.Account{ID: "123456789012"},
		Regions:     []cloudcontext.Region{{Name: "us-east-1", Enabled: true}},
		Network: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"vpc-1": {
				ID:        "vpc-1",
				Type:      "aws_vpc",
				Region:    "us-east-1",
				AccountID: "123456789012",
			},
			"sg-public": {
				ID:        "sg-public",
				Type:      "aws_security_group",
				Region:    "us-east-1",
				AccountID: "123456789012",
				Public:    &public,
			},
		}},
		Edge: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/public/1": {
				ARN:       "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/public/1",
				Type:      "aws_lb",
				Region:    "us-east-1",
				AccountID: "123456789012",
				Public:    &public,
			},
		}},
		Compute: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"arn:aws:lambda:us-east-1:123456789012:function:api": {
				ARN:       "arn:aws:lambda:us-east-1:123456789012:function:api",
				Type:      "aws_lambda_function",
				Region:    "us-east-1",
				AccountID: "123456789012",
			},
		}},
		IAM: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"arn:aws:iam::123456789012:role/app": {
				ARN:       "arn:aws:iam::123456789012:role/app",
				Type:      "aws_iam_role",
				AccountID: "123456789012",
			},
			"arn:aws:iam::123456789012:policy/app": {
				ARN:       "arn:aws:iam::123456789012:policy/app",
				Type:      "aws_iam_policy",
				AccountID: "123456789012",
			},
		}},
		Data: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"arn:aws:rds:us-east-1:123456789012:db:customer": {
				ARN:                  "arn:aws:rds:us-east-1:123456789012:db:customer",
				Type:                 "aws_db_instance",
				Region:               "us-east-1",
				AccountID:            "123456789012",
				SensitiveData:        true,
				Sensitivity:          cloudcontext.Sensitivity{Data: true, Reason: "customer data"},
				RelatedSensitiveData: []string{"customer records"},
			},
		}},
		Relationships: []cloudcontext.Relationship{
			{From: "internet", To: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/public/1", Type: "routes_to", Source: "aws_elbv2", Confidence: "high"},
			{From: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/public/1", To: "arn:aws:lambda:us-east-1:123456789012:function:api", Type: "invokes", Source: "aws_elbv2", Confidence: "high"},
			{From: "arn:aws:lambda:us-east-1:123456789012:function:api", To: "arn:aws:rds:us-east-1:123456789012:db:customer", Type: "network_reaches", Source: "aws_ec2", Confidence: "high"},
			{From: "arn:aws:lambda:us-east-1:123456789012:function:api", To: "arn:aws:iam::123456789012:role/app", Type: "uses_role", Source: "aws_lambda", Confidence: "high"},
			{From: "arn:aws:iam::123456789012:role/app", To: "arn:aws:iam::123456789012:policy/app", Type: "attached_policy", Source: "aws_iam", Confidence: "high"},
			{From: "arn:aws:iam::123456789012:policy/app", To: "action:s3:GetObject", Type: "grants_action", Source: "aws_iam", Confidence: "high"},
			{From: "arn:aws:iam::123456789012:policy/app", To: "*", Type: "grants_resource", Source: "aws_iam", Confidence: "high"},
		},
	}
}

func sparseVPCSnapshot() cloudcontext.Snapshot {
	public := true
	return cloudcontext.Snapshot{
		Version:     cloudcontext.Version,
		Provider:    cloudcontext.ProviderAWS,
		GeneratedAt: "2026-07-08T00:00:00Z",
		Account:     cloudcontext.Account{ID: "927120871591"},
		Regions:     []cloudcontext.Region{{Name: "us-east-1", Enabled: true}},
		Network: cloudcontext.ResourceSet{Resources: map[string]cloudcontext.Resource{
			"vpc-0b744527525aa41a9": {
				ID:         "vpc-0b744527525aa41a9",
				Type:       "aws_vpc",
				Region:     "us-east-1",
				AccountID:  "927120871591",
				Attributes: map[string]string{"cidr_block": "172.31.0.0/16"},
			},
			"subnet-empty-a": {
				ID:         "subnet-empty-a",
				Type:       "aws_subnet",
				Region:     "us-east-1",
				AccountID:  "927120871591",
				Attributes: map[string]string{"vpc_id": "vpc-0b744527525aa41a9", "cidr_block": "172.31.0.0/20"},
			},
			"subnet-empty-b": {
				ID:         "subnet-empty-b",
				Type:       "aws_subnet",
				Region:     "us-east-1",
				AccountID:  "927120871591",
				Attributes: map[string]string{"vpc_id": "vpc-0b744527525aa41a9", "cidr_block": "172.31.16.0/20"},
			},
			"rtb-0c673ec5e49e9a7aa": {
				ID:         "rtb-0c673ec5e49e9a7aa",
				Type:       "aws_route_table",
				Region:     "us-east-1",
				AccountID:  "927120871591",
				Attributes: map[string]string{"vpc_id": "vpc-0b744527525aa41a9"},
			},
			"default": {
				ID:         "default",
				Type:       "aws_security_group",
				Region:     "us-east-1",
				AccountID:  "927120871591",
				Attributes: map[string]string{"vpc_id": "vpc-0b744527525aa41a9"},
			},
			"igw-028372dce8609f352": {
				ID:        "igw-028372dce8609f352",
				Type:      "aws_internet_gateway",
				Region:    "us-east-1",
				AccountID: "927120871591",
				Public:    &public,
			},
		}},
		Relationships: []cloudcontext.Relationship{
			{From: "rtb-0c673ec5e49e9a7aa", To: "igw-028372dce8609f352", Type: "routes_to", Source: "aws_ec2", Confidence: "high"},
		},
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
