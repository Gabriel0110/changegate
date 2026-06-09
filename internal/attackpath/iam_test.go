package attackpath

import (
	"testing"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestActionMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern string
		action  string
		want    bool
	}{
		{name: "exact", pattern: "iam:PassRole", action: "iam:PassRole", want: true},
		{name: "service wildcard", pattern: "lambda:*", action: "lambda:UpdateFunctionCode", want: true},
		{name: "global wildcard", pattern: "*", action: "ecs:RunTask", want: true},
		{name: "prefix wildcard", pattern: "secretsmanager:Get*", action: "secretsmanager:GetSecretValue", want: true},
		{name: "miss", pattern: "s3:GetObject", action: "iam:PassRole", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ActionMatches(tt.pattern, tt.action); got != tt.want {
				t.Fatalf("ActionMatches(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
			}
		})
	}
}

func TestParsePolicyStatements(t *testing.T) {
	t.Parallel()
	statements, ok := parsePolicyStatements(`{
	  "Version": "2012-10-17",
	  "Statement": {
	    "Effect": "Allow",
	    "Action": ["iam:PassRole", "lambda:UpdateFunctionCode"],
	    "Resource": "*",
	    "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
	  }
	}`)
	if !ok || len(statements) != 1 {
		t.Fatalf("parse ok=%v len=%d", ok, len(statements))
	}
	if len(statements[0].Actions) != 2 || statements[0].Actions[0] != "iam:PassRole" {
		t.Fatalf("actions = %#v", statements[0].Actions)
	}
	if len(statements[0].Condition) == 0 {
		t.Fatal("expected condition to be preserved")
	}
}

func TestDetectIAMPassRoleAndLambdaUpdateBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": ["iam:PassRole", "lambda:UpdateFunctionCode"],
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	if len(paths) == 0 {
		t.Fatal("expected IAM attack path")
	}
	path := findIAMPath(paths, "iam:PassRole")
	if path == nil {
		t.Fatalf("missing passrole path: %#v", paths)
	}
	if path.Decision != model.DecisionBlock || path.Confidence != model.ConfidenceHigh {
		t.Fatalf("unexpected decision/confidence: %#v", path)
	}
}

func TestDetectIAMPassRoleAndLambdaCreateFunctionBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findIAMPath(paths, "lambda:CreateFunction")
	if path == nil {
		t.Fatalf("missing lambda create function path: %#v", paths)
	}
	if path.Decision != model.DecisionBlock || path.Target != "aws_iam_role.admin_execution" {
		t.Fatalf("unexpected path: %#v", path)
	}
}

func TestDetectIAMPassRoleAndLambdaCreateFunctionWithoutInvokeWarns(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": ["iam:PassRole", "lambda:CreateFunction"],
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{IncludeWarnings: true})
	path := findIAMPath(paths, "lambda:CreateFunction")
	if path == nil {
		t.Fatalf("missing lambda create warning path: %#v", paths)
	}
	if path.Decision != model.DecisionWarn || path.Confidence != model.ConfidenceMedium {
		t.Fatalf("unexpected path: %#v", path)
	}
}

func TestDetectIAMAssumeAdminRoleBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_role.admin_execution", graph.EdgeCanAssume))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findIAMPath(paths, "sts:AssumeRole")
	if path == nil {
		t.Fatalf("missing assume-role path: %#v", paths)
	}
	if path.Decision != model.DecisionBlock {
		t.Fatalf("decision = %q, want block", path.Decision)
	}
}

func TestDetectIAMLambdaUpdateExecutionRoleBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_lambda_function.worker"] = workloadNode("aws_lambda_function.worker", "aws_lambda_function")
	g.Edges = append(g.Edges, edge("aws_lambda_function.worker", "aws_iam_role.admin_execution", graph.EdgeCanAssume))
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": "lambda:UpdateFunctionCode",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findIAMPath(paths, "lambda:UpdateFunctionCode")
	if path == nil {
		t.Fatalf("missing lambda update path: %#v", paths)
	}
	if path.Target != "aws_iam_role.admin_execution" {
		t.Fatalf("target = %q, want admin role", path.Target)
	}
}

func TestDetectIAMECSUpdateSensitiveTaskRoleBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_ecs_service.admin"] = workloadNode("aws_ecs_service.admin", "aws_ecs_service")
	g.Nodes["aws_ecs_task_definition.admin"] = workloadNode("aws_ecs_task_definition.admin", "aws_ecs_task_definition")
	g.Nodes["aws_iam_role.task"] = principalNode("aws_iam_role.task", "task")
	g.Nodes["aws_secretsmanager_secret.customer"] = &graph.Node{ID: "aws_secretsmanager_secret.customer", Address: "aws_secretsmanager_secret.customer", Type: "aws_secretsmanager_secret", Kind: graph.NodeSecret, Name: "customer"}
	g.Edges = append(g.Edges,
		edge("aws_ecs_service.admin", "aws_ecs_task_definition.admin", graph.EdgeDependsOn),
		edge("aws_ecs_task_definition.admin", "aws_iam_role.task", graph.EdgeCanPassRole),
		edge("aws_iam_role.task", "aws_secretsmanager_secret.customer", graph.EdgeReadsSecret),
	)
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": "ecs:UpdateService",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findIAMPath(paths, "ecs:UpdateService")
	if path == nil {
		t.Fatalf("missing ecs update path: %#v", paths)
	}
	if path.Decision != model.DecisionBlock {
		t.Fatalf("decision = %q, want block", path.Decision)
	}
}

func TestDetectIAMComplexConditionWarnsNotHighConfidenceBlock(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": ["iam:PassRole", "lambda:UpdateFunctionCode"],
	    "Resource": "*",
	    "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{IncludeWarnings: true})
	path := findIAMPath(paths, "iam:PassRole")
	if path == nil {
		t.Fatalf("missing warning path: %#v", paths)
	}
	if path.Decision != model.DecisionWarn || path.Confidence != model.ConfidenceMedium {
		t.Fatalf("expected medium-confidence warning, got %#v", path)
	}
}

func TestDetectIAMExplicitDenyAvoidsHighConfidenceBlock(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [
	    {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:UpdateFunctionCode"], "Resource": "*"},
	    {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}
	  ]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	if path := findIAMPath(paths, "iam:PassRole"); path != nil {
		t.Fatalf("explicit deny should avoid default high-confidence path, got %#v", path)
	}
}

func TestParsePolicyStatementsSeparatesNotAction(t *testing.T) {
	t.Parallel()
	statements, ok := parsePolicyStatements(`{
	  "Statement": [{
	    "Effect": "Allow",
	    "NotAction": "iam:DeleteRole",
	    "NotResource": "arn:aws:iam::*:role/breakglass-*"
	  }]
	}`)
	if !ok || len(statements) != 1 {
		t.Fatalf("parse ok=%v len=%d", ok, len(statements))
	}
	if len(statements[0].Actions) != 0 || len(statements[0].NotActions) != 1 {
		t.Fatalf("actions=%#v not_actions=%#v", statements[0].Actions, statements[0].NotActions)
	}
	if len(statements[0].Resources) != 0 || len(statements[0].NotResources) != 1 {
		t.Fatalf("resources=%#v not_resources=%#v", statements[0].Resources, statements[0].NotResources)
	}
}

func TestDetectIAMBroadNotActionWarns(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "NotAction": "iam:DeleteRole",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{IncludeWarnings: true})
	path := findIAMPath(paths, "iam:PassRole")
	if path == nil {
		t.Fatalf("missing broad NotAction path: %#v", paths)
	}
	if path.Decision != model.DecisionWarn || path.Confidence != model.ConfidenceMedium {
		t.Fatalf("unexpected decision/confidence: %#v", path)
	}
	if len(path.FindingRuleIDs) == 0 || path.FindingRuleIDs[0] != RuleIAMBroadNotActionEscalation {
		t.Fatalf("finding rule ids = %#v", path.FindingRuleIDs)
	}
}

func TestDetectIAMPolicyMutationEscalationBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": "iam:PutRolePolicy",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findIAMPath(paths, "iam:PutRolePolicy")
	if path == nil {
		t.Fatalf("missing policy mutation path: %#v", paths)
	}
	if path.Decision != model.DecisionBlock || path.Target != "aws_iam_role.admin_execution" {
		t.Fatalf("unexpected path: %#v", path)
	}
	if len(path.FindingRuleIDs) == 0 || path.FindingRuleIDs[0] != RuleIAMPolicyMutationEscalation {
		t.Fatalf("finding rule ids = %#v", path.FindingRuleIDs)
	}
}

func TestDetectIAMRoleAssumptionChainBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_role.intermediate"] = principalNode("aws_iam_role.intermediate", "intermediate")
	g.Edges = append(g.Edges,
		edge("aws_iam_role.github_actions", "aws_iam_role.intermediate", graph.EdgeCanAssume),
		edge("aws_iam_role.intermediate", "aws_iam_role.admin_execution", graph.EdgeCanAssume),
	)

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	var chain *AttackPath
	for i := range paths {
		if paths[i].Metadata["attack_pattern"] == "role_assumption_chain" {
			chain = &paths[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("missing role assumption chain: %#v", paths)
	}
	if chain.Decision != model.DecisionBlock || len(chain.Steps) != 2 {
		t.Fatalf("unexpected chain: %#v", chain)
	}
}

func TestPathfindingCatalogCoverage(t *testing.T) {
	t.Parallel()
	if got := PathfindingCatalogCoverage(); got < 80 {
		t.Fatalf("catalog coverage = %d, want at least 80 pathfinding.cloud paths", got)
	}
}

func TestDetectPathfindingNewPassRoleServicePathBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findPathfindingPath(paths, "codebuild-001")
	if path == nil {
		t.Fatalf("missing codebuild pathfinding path: %#v", paths)
	}
	if path.Decision != model.DecisionBlock || path.Target != "aws_iam_role.admin_execution" {
		t.Fatalf("unexpected path: %#v", path)
	}
	if len(path.FindingRuleIDs) == 0 || path.FindingRuleIDs[0] != RuleIAMPathfindingCatalogEscalation {
		t.Fatalf("finding rule ids = %#v", path.FindingRuleIDs)
	}
}

func TestDetectPathfindingExistingPassRolePathRequiresGraphTarget(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_codebuild_project.admin"] = workloadNode("aws_codebuild_project.admin", "aws_codebuild_project")
	g.Edges = append(g.Edges, edge("aws_codebuild_project.admin", "aws_iam_role.admin_execution", graph.EdgeCanAssume))
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": "codebuild:StartBuild",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	if path := findPathfindingPath(paths, "codebuild-002"); path == nil {
		t.Fatalf("missing existing CodeBuild pathfinding path: %#v", paths)
	}

	noTarget := iamBaseGraph()
	noTarget.Nodes["aws_iam_policy.deploy"] = g.Nodes["aws_iam_policy.deploy"]
	noTarget.Edges = append(noTarget.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))
	paths = DetectIAMPrivilegeEscalation(noTarget, IAMDetectionOptions{})
	if path := findPathfindingPath(paths, "codebuild-002"); path != nil {
		t.Fatalf("expected no path without existing privileged target, got %#v", path)
	}
}

func TestDetectPathfindingSelfEscalationBlocks(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": "iam:AttachUserPolicy",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findPathfindingPath(paths, "iam-008")
	if path == nil {
		t.Fatalf("missing self-escalation path: %#v", paths)
	}
	if path.Decision != model.DecisionBlock || path.Target != "aws_iam_role.github_actions" {
		t.Fatalf("unexpected path: %#v", path)
	}
}

func TestDetectPathfindingPrincipalAccessBlocksPrivilegedUserCredentialPath(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_user.admin"] = &graph.Node{ID: "aws_iam_user.admin", Address: "aws_iam_user.admin", Type: "aws_iam_user", Kind: graph.NodePrincipal, Name: "admin-user", Environment: "production"}
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": "iam:CreateLoginProfile",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{})
	path := findPathfindingPath(paths, "iam-004")
	if path == nil {
		t.Fatalf("missing create-login-profile path: %#v", paths)
	}
	if path.Target != "aws_iam_user.admin" {
		t.Fatalf("target = %q, want admin user", path.Target)
	}
}

func TestDetectPathfindingBroadNotActionWarns(t *testing.T) {
	t.Parallel()
	g := iamBaseGraph()
	g.Nodes["aws_iam_policy.deploy"] = policyNode("aws_iam_policy.deploy", `{
	  "Statement": [{
	    "Effect": "Allow",
	    "NotAction": "iam:DeleteRole",
	    "Resource": "*"
	  }]
	}`)
	g.Edges = append(g.Edges, edge("aws_iam_role.github_actions", "aws_iam_policy.deploy", graph.EdgeAttachedTo))

	paths := DetectIAMPrivilegeEscalation(g, IAMDetectionOptions{IncludeWarnings: true})
	path := findPathfindingPath(paths, "codebuild-001")
	if path == nil {
		t.Fatalf("missing broad NotAction catalog path: %#v", paths)
	}
	if path.Decision != model.DecisionWarn || path.Confidence != model.ConfidenceMedium {
		t.Fatalf("unexpected path: %#v", path)
	}
}

func iamBaseGraph() *graph.Graph {
	return &graph.Graph{Nodes: map[graph.ResourceID]*graph.Node{
		"aws_iam_role.github_actions":  principalNode("aws_iam_role.github_actions", "github_actions"),
		"aws_iam_role.admin_execution": adminRoleNode(),
	}}
}

func principalNode(id graph.ResourceID, name string) *graph.Node {
	return &graph.Node{ID: id, Address: string(id), Type: "aws_iam_role", Kind: graph.NodePrincipal, Name: name}
}

func adminRoleNode() *graph.Node {
	return &graph.Node{
		ID:          "aws_iam_role.admin_execution",
		Address:     "aws_iam_role.admin_execution",
		Type:        "aws_iam_role",
		Kind:        graph.NodePrincipal,
		Name:        "admin_execution",
		Environment: "production",
	}
}

func policyNode(id graph.ResourceID, policy string) *graph.Node {
	return &graph.Node{
		ID:      id,
		Address: string(id),
		Type:    "aws_iam_policy",
		Kind:    graph.NodePolicy,
		Name:    string(id),
		Values:  map[string]any{"policy": policy},
	}
}

func workloadNode(id graph.ResourceID, typ string) *graph.Node {
	return &graph.Node{ID: id, Address: string(id), Type: typ, Kind: graph.NodeWorkload, Name: string(id)}
}

func findIAMPath(paths []AttackPath, action string) *AttackPath {
	for i := range paths {
		for _, step := range paths[i].Steps {
			if step.Action == action {
				return &paths[i]
			}
		}
	}
	return nil
}

func findPathfindingPath(paths []AttackPath, id string) *AttackPath {
	for i := range paths {
		if paths[i].Metadata["pathfinding_id"] == id {
			return &paths[i]
		}
	}
	return nil
}
