package attackpath

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

// IAMDetectionOptions controls IAM attack path detection.
type IAMDetectionOptions struct {
	IncludeWarnings bool
}

type iamGrant struct {
	Principal      graph.ResourceID
	Source         graph.ResourceID
	Actions        []string
	NotActions     []string
	Resources      []string
	NotResources   []string
	Confidence     model.Confidence
	HasDeny        bool
	Complex        bool
	BroadNotAction bool
}

type iamDocument struct {
	Statement any `json:"Statement"`
}

type iamStatement struct {
	Effect       string
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	Condition    map[string]any
}

// ActionMatches reports whether an IAM action pattern covers an action.
func ActionMatches(pattern string, action string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	action = strings.ToLower(strings.TrimSpace(action))
	if pattern == "*" || pattern == action {
		return true
	}
	if strings.HasSuffix(pattern, ":*") {
		return strings.HasPrefix(action, strings.TrimSuffix(pattern, "*"))
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(action, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// DetectIAMPrivilegeEscalation finds high-signal IAM privilege escalation paths.
func DetectIAMPrivilegeEscalation(g *graph.Graph, opts IAMDetectionOptions) []AttackPath {
	if g == nil {
		return nil
	}
	grants := collectIAMGrants(g)
	paths := make([]AttackPath, 0)
	paths = append(paths, detectPassRoleComputeMutation(g, grants, opts)...)
	paths = append(paths, detectAssumeAdminRole(g, grants, opts)...)
	paths = append(paths, detectRoleAssumptionChains(g, opts)...)
	paths = append(paths, detectFunctionUpdateRoleAccess(g, grants, opts)...)
	paths = append(paths, detectECSUpdateServiceRoleAccess(g, grants, opts)...)
	paths = append(paths, detectIAMPolicyMutationEscalation(g, grants, opts)...)
	paths = append(paths, detectPathfindingCatalogEscalation(g, grants, opts)...)
	return Normalize(paths)
}

func detectPassRoleComputeMutation(g *graph.Graph, grants []iamGrant, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	for _, grant := range grants {
		if !grantAllows(grant, "iam:PassRole") {
			continue
		}
		mutation := firstAllowedAction(grant, "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:CreateFunction", "ecs:RunTask", "ecs:UpdateService", "ecs:RegisterTaskDefinition")
		if mutation == "" {
			continue
		}
		mutationConfidenceAdjustment := model.Confidence("")
		if strings.EqualFold(mutation, "lambda:CreateFunction") && !grantAllows(grant, "lambda:InvokeFunction") {
			mutationConfidenceAdjustment = model.ConfidenceMedium
		}
		for _, role := range passableRoles(g, grant) {
			decision, severity, confidence := iamDecisionForTarget(g.Nodes[role], grant)
			if mutationConfidenceAdjustment != "" && confidenceRank(mutationConfidenceAdjustment) < confidenceRank(confidence) {
				confidence = mutationConfidenceAdjustment
				decision, severity = iamDecision(confidence, g.Nodes[role])
			}
			if decision == model.DecisionWarn && !opts.IncludeWarnings {
				continue
			}
			out = append(out, AttackPath{
				Type:             TypeIAMPrivilegeEscalation,
				Title:            fmt.Sprintf("Principal %s can pass %s and run %s", grant.Principal, role, mutation),
				Severity:         severity,
				Confidence:       confidence,
				ConfidenceReason: iamConfidenceReason(confidence, grant, "iam:PassRole plus compute mutation can execute code with the target role"),
				Decision:         decision,
				Principal:        string(grant.Principal),
				Target:           string(role),
				Steps: []Step{
					iamStep(grant.Principal, role, "iam:PassRole", graph.EdgeCanPassRole, "principal can pass a privileged or sensitive execution role", confidence),
					iamStep(grant.Principal, mutationTarget(mutation), mutation, graph.EdgeGrantsPermission, "principal can mutate or launch compute that can use the passed role", confidence),
				},
				Evidence:    iamEvidence(grant, role, mutation),
				Mitigations: []string{"Scope iam:PassRole to non-privileged execution roles and exact services.", "Separate compute mutation permissions from pass-role permissions."},
				References:  []string{"docs/attack-paths.md"},
				Metadata:    iamMetadata(grant, map[string]string{"attack_pattern": "passrole_compute_mutation"}),
			})
		}
	}
	return out
}

func detectAssumeAdminRole(g *graph.Graph, grants []iamGrant, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	seen := make(map[string]bool)
	for _, edge := range g.Edges {
		if edge.Type != graph.EdgeCanAssume || !privilegedOrSensitiveRole(g, edge.To) {
			continue
		}
		key := string(edge.From) + "\x00" + string(edge.To)
		seen[key] = true
		confidence := confidenceFromGraph(edge.Confidence, edge.Source)
		decision, severity := iamDecision(confidence, g.Nodes[edge.To])
		if decision == model.DecisionWarn && !opts.IncludeWarnings {
			continue
		}
		out = append(out, AttackPath{
			Type:             TypeIAMPrivilegeEscalation,
			Title:            fmt.Sprintf("Principal %s can assume privileged role %s", edge.From, edge.To),
			Severity:         severity,
			Confidence:       confidence,
			Decision:         decision,
			Principal:        string(edge.From),
			Target:           string(edge.To),
			ConfidenceReason: iamGraphConfidenceReason(confidence, "explicit role assumption edge reaches a privileged or sensitive role"),
			Steps:            []Step{iamGraphStep(edge.From, edge.To, "sts:AssumeRole", graph.EdgeCanAssume, edgeExplanationFromGraph(edge), edge)},
			Evidence: []model.Evidence{{
				Type:     "attack_path.iam",
				Resource: string(edge.To),
				Path:     "graph.can_assume",
				Value:    []string{string(edge.From), string(edge.To)},
				Message:  "principal can assume a privileged or sensitive role",
			}},
			Mitigations: []string{"Remove broad trust or require tightly scoped conditions and approval for privileged role assumption."},
			References:  []string{"docs/attack-paths.md"},
		})
	}
	for _, grant := range grants {
		if !grantAllows(grant, "sts:AssumeRole") {
			continue
		}
		for _, role := range assumableRoles(g, grant) {
			key := string(grant.Principal) + "\x00" + string(role)
			if seen[key] || !privilegedOrSensitiveRole(g, role) {
				continue
			}
			decision, severity, confidence := iamDecisionForTarget(g.Nodes[role], grant)
			if decision == model.DecisionWarn && !opts.IncludeWarnings {
				continue
			}
			out = append(out, AttackPath{
				Type:             TypeIAMPrivilegeEscalation,
				Title:            fmt.Sprintf("Principal %s can assume privileged role %s", grant.Principal, role),
				Severity:         severity,
				Confidence:       confidence,
				ConfidenceReason: iamConfidenceReason(confidence, grant, "policy allows role assumption to a privileged or sensitive role"),
				Decision:         decision,
				Principal:        string(grant.Principal),
				Target:           string(role),
				Steps:            []Step{iamStep(grant.Principal, role, "sts:AssumeRole", graph.EdgeCanAssume, "policy allows role assumption", confidence)},
				Evidence:         iamEvidence(grant, role, "sts:AssumeRole"),
				Mitigations:      []string{"Scope sts:AssumeRole to exact non-admin roles and require restrictive trust conditions."},
				References:       []string{"docs/attack-paths.md"},
				Metadata:         iamMetadata(grant, map[string]string{"attack_pattern": "assume_privileged_role"}),
			})
		}
	}
	return out
}

func detectRoleAssumptionChains(g *graph.Graph, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	for _, start := range sortedNodesByKind(g, graph.NodePrincipal) {
		paths := roleAssumptionGraphPaths(g, start, 4)
		for _, path := range paths {
			target := pathTarget(path)
			if len(path.Edges) < 2 || !privilegedOrSensitiveRole(g, target) {
				continue
			}
			confidence := confidenceForPath(path)
			decision, severity := iamDecision(confidence, g.Nodes[target])
			if decision == model.DecisionWarn && !opts.IncludeWarnings {
				continue
			}
			out = append(out, AttackPath{
				Type:             TypeIAMPrivilegeEscalation,
				Title:            fmt.Sprintf("Principal %s can reach privileged role %s through role assumption chain", start, target),
				Severity:         severity,
				Confidence:       confidence,
				ConfidenceReason: iamGraphConfidenceReason(confidence, "multiple explicit role assumption edges connect the principal to a privileged or sensitive role"),
				Decision:         decision,
				Principal:        string(start),
				Target:           string(target),
				Steps:            stepsFromGraphPath(path),
				Evidence: []model.Evidence{{
					Type:     "attack_path.iam",
					Resource: string(target),
					Path:     "graph.assume_role_chain",
					Value:    graphPathNodes(path),
					Message:  "principal can reach a privileged or sensitive role through chained role assumptions",
				}},
				Mitigations: []string{"Break chained trust by removing unnecessary intermediate role assumptions.", "Require restrictive external IDs, audience, subject, or principal conditions on each role trust edge."},
				References:  []string{"docs/attack-paths.md"},
				Metadata:    map[string]string{"attack_pattern": "role_assumption_chain", "chain_length": fmt.Sprint(len(path.Edges))},
			})
		}
	}
	return out
}

func detectFunctionUpdateRoleAccess(g *graph.Graph, grants []iamGrant, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	for _, grant := range grants {
		if !grantAllows(grant, "lambda:UpdateFunctionCode") {
			continue
		}
		for _, fn := range sortedNodesByKind(g, graph.NodeWorkload) {
			if g.Nodes[fn].Type != "aws_lambda_function" || !resourceCovered(grant.Resources, g.Nodes[fn]) {
				continue
			}
			for _, role := range rolesUsedBy(g, fn) {
				if !privilegedOrSensitiveRole(g, role) {
					continue
				}
				decision, severity, confidence := iamDecisionForTarget(g.Nodes[role], grant)
				if decision == model.DecisionWarn && !opts.IncludeWarnings {
					continue
				}
				out = append(out, AttackPath{
					Type:             TypeIAMPrivilegeEscalation,
					Title:            fmt.Sprintf("Principal %s can update Lambda %s with privileged execution role", grant.Principal, fn),
					Severity:         severity,
					Confidence:       confidence,
					ConfidenceReason: iamConfidenceReason(confidence, grant, "policy allows updating executable Lambda code on a function that uses privileged or sensitive role access"),
					Decision:         decision,
					Principal:        string(grant.Principal),
					Target:           string(role),
					Steps: []Step{
						iamStep(grant.Principal, fn, "lambda:UpdateFunctionCode", graph.EdgeGrantsPermission, "principal can update executable Lambda code", confidence),
						iamStep(fn, role, "uses execution role", graph.EdgeCanAssume, "function executes with privileged or sensitive role access", confidence),
					},
					Evidence:    iamEvidence(grant, role, "lambda:UpdateFunctionCode"),
					Mitigations: []string{"Remove function update access or move the function to a least-privilege execution role."},
					References:  []string{"docs/attack-paths.md"},
					Metadata:    iamMetadata(grant, map[string]string{"attack_pattern": "lambda_update_execution_role"}),
				})
			}
		}
	}
	return out
}

func detectECSUpdateServiceRoleAccess(g *graph.Graph, grants []iamGrant, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	for _, grant := range grants {
		if !grantAllows(grant, "ecs:UpdateService") {
			continue
		}
		for _, service := range sortedNodesByKind(g, graph.NodeWorkload) {
			if g.Nodes[service].Type != "aws_ecs_service" || !resourceCovered(grant.Resources, g.Nodes[service]) {
				continue
			}
			for _, role := range ecsServiceRoles(g, service) {
				if !sensitiveRole(g, role) {
					continue
				}
				decision, severity, confidence := iamDecisionForTarget(g.Nodes[role], grant)
				if decision == model.DecisionWarn && !opts.IncludeWarnings {
					continue
				}
				out = append(out, AttackPath{
					Type:             TypeIAMPrivilegeEscalation,
					Title:            fmt.Sprintf("Principal %s can update ECS service %s with sensitive task role", grant.Principal, service),
					Severity:         severity,
					Confidence:       confidence,
					ConfidenceReason: iamConfidenceReason(confidence, grant, "policy allows updating ECS service execution that uses sensitive role access"),
					Decision:         decision,
					Principal:        string(grant.Principal),
					Target:           string(role),
					Steps: []Step{
						iamStep(grant.Principal, service, "ecs:UpdateService", graph.EdgeGrantsPermission, "principal can update service task execution", confidence),
						iamStep(service, role, "uses task role", graph.EdgeCanPassRole, "service task role can access sensitive data or secrets", confidence),
					},
					Evidence:    iamEvidence(grant, role, "ecs:UpdateService"),
					Mitigations: []string{"Remove service update access or use a task role without sensitive data access."},
					References:  []string{"docs/attack-paths.md"},
					Metadata:    iamMetadata(grant, map[string]string{"attack_pattern": "ecs_update_sensitive_task_role"}),
				})
			}
		}
	}
	return out
}

type iamEscalationPattern struct {
	ID          string
	Actions     []string
	Title       string
	Explanation string
	Mitigations []string
}

var nativeIAMEscalationPatterns = []iamEscalationPattern{
	{
		ID:          "iam_policy_inline_role_escalation",
		Actions:     []string{"iam:PutRolePolicy"},
		Title:       "Principal %s can attach inline administrator policy to %s",
		Explanation: "principal can add inline role policy, which can grant administrator or sensitive permissions",
		Mitigations: []string{"Remove iam:PutRolePolicy from deploy roles or scope it to non-privileged break-glass workflows.", "Require reviewed policy-as-code changes instead of runtime IAM policy mutation."},
	},
	{
		ID:          "iam_policy_attach_admin_escalation",
		Actions:     []string{"iam:AttachRolePolicy"},
		Title:       "Principal %s can attach managed administrator policy to %s",
		Explanation: "principal can attach managed policies to a role that is or can become privileged",
		Mitigations: []string{"Remove iam:AttachRolePolicy from non-security automation.", "Restrict attachable policy ARNs to approved least-privilege policies."},
	},
	{
		ID:          "iam_policy_version_escalation",
		Actions:     []string{"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"},
		Title:       "Principal %s can replace default policy version for %s",
		Explanation: "principal can create and promote a new policy version with expanded permissions",
		Mitigations: []string{"Separate policy version creation from default-version promotion.", "Require code review and approval for IAM policy mutation permissions."},
	},
	{
		ID:          "iam_trust_policy_takeover",
		Actions:     []string{"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"},
		Title:       "Principal %s can rewrite trust and assume %s",
		Explanation: "principal can alter role trust and then assume the privileged or sensitive role",
		Mitigations: []string{"Remove iam:UpdateAssumeRolePolicy from deploy roles.", "Require narrowly scoped trust policy conditions for privileged roles."},
	},
	{
		ID:          "iam_user_access_key_escalation",
		Actions:     []string{"iam:CreateAccessKey"},
		Title:       "Principal %s can create credentials for privileged user %s",
		Explanation: "principal can create long-lived access keys for an IAM user with privileged or sensitive access",
		Mitigations: []string{"Disallow iam:CreateAccessKey for privileged users.", "Use short-lived federation and monitor credential creation events."},
	},
}

func detectIAMPolicyMutationEscalation(g *graph.Graph, grants []iamGrant, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	for _, grant := range grants {
		for _, pattern := range nativeIAMEscalationPatterns {
			if !grantAllowsAll(grant, pattern.Actions...) {
				continue
			}
			for _, target := range escalationTargets(g, grant, pattern) {
				decision, severity, confidence := iamDecisionForTarget(g.Nodes[target], grant)
				if grant.BroadNotAction {
					confidence = model.ConfidenceMedium
					decision, severity = iamDecision(confidence, g.Nodes[target])
				}
				if decision == model.DecisionWarn && !opts.IncludeWarnings {
					continue
				}
				steps := make([]Step, 0, len(pattern.Actions))
				for _, action := range pattern.Actions {
					steps = append(steps, iamStep(grant.Principal, target, action, graph.EdgeGrantsPermission, pattern.Explanation, confidence))
				}
				out = append(out, AttackPath{
					Type:             TypeIAMPrivilegeEscalation,
					Title:            fmt.Sprintf(pattern.Title, grant.Principal, target),
					Severity:         severity,
					Confidence:       confidence,
					ConfidenceReason: iamConfidenceReason(confidence, grant, pattern.Explanation),
					Decision:         decision,
					Principal:        string(grant.Principal),
					Target:           string(target),
					Steps:            steps,
					Evidence:         iamEvidence(grant, target, strings.Join(pattern.Actions, "+")),
					Mitigations:      pattern.Mitigations,
					References:       []string{"docs/attack-paths.md", "https://pathfinding.cloud/paths/", "https://github.com/DataDog/pathfinding.cloud"},
					Metadata: iamMetadata(grant, map[string]string{
						"attack_pattern":     pattern.ID,
						"pathfinding_source": "DataDog/pathfinding.cloud research catalog",
					}),
				})
			}
		}
	}
	return out
}

func detectPathfindingCatalogEscalation(g *graph.Graph, grants []iamGrant, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	for _, grant := range grants {
		for _, entry := range pathfindingCatalog() {
			if catalogCoveredByNativeDetector(entry) || !grantAllowsAll(grant, entry.RequiredActions...) {
				continue
			}
			for _, target := range pathfindingTargets(g, grant, entry) {
				decision, severity, confidence := iamDecisionForTarget(g.Nodes[target], grant)
				if grant.BroadNotAction {
					confidence = model.ConfidenceMedium
					decision, severity = iamDecision(confidence, g.Nodes[target])
				}
				if decision == model.DecisionWarn && !opts.IncludeWarnings {
					continue
				}
				out = append(out, AttackPath{
					Type:             TypeIAMPrivilegeEscalation,
					Title:            fmt.Sprintf("Principal %s matches pathfinding.cloud path %s: %s", grant.Principal, entry.ID, entry.Name),
					Severity:         severity,
					Confidence:       confidence,
					ConfidenceReason: iamConfidenceReason(confidence, grant, "pathfinding.cloud IAM privilege-escalation prerequisites are satisfied by policy and graph evidence"),
					Decision:         decision,
					Principal:        string(grant.Principal),
					Target:           string(target),
					Steps:            pathfindingSteps(grant, target, entry, confidence),
					Evidence:         pathfindingEvidence(grant, target, entry),
					Mitigations:      pathfindingMitigations(entry),
					References:       pathfindingReferences(entry),
					Metadata: iamMetadata(grant, map[string]string{
						"attack_pattern":          "pathfinding_catalog",
						"pathfinding_id":          entry.ID,
						"pathfinding_category":    entry.Category,
						"pathfinding_services":    strings.Join(entry.Services, ","),
						"pathfinding_source":      "DataDog/pathfinding.cloud research catalog",
						"pathfinding_source_path": entry.SourcePath,
					}),
				})
			}
		}
	}
	return out
}

func catalogCoveredByNativeDetector(entry pathfindingCatalogEntry) bool {
	switch entry.ID {
	case "lambda-001", "lambda-003", "lambda-004", "ecs-002", "ecs-004", "ecs-008", "sts-001":
		return true
	}
	if strings.HasPrefix(entry.ID, "iam-") {
		switch entry.ID {
		case "iam-001", "iam-002", "iam-005", "iam-009", "iam-014", "iam-016", "iam-017", "iam-021":
			return true
		}
	}
	return false
}

func pathfindingTargets(g *graph.Graph, grant iamGrant, entry pathfindingCatalogEntry) []graph.ResourceID {
	switch entry.Category {
	case "new-passrole":
		return pathfindingPassRoleTargets(g, grant)
	case "existing-passrole":
		return pathfindingExistingResourceTargets(g, grant, entry)
	case "self-escalation", "principal-access":
		return pathfindingPrincipalTargets(g, grant, entry)
	default:
		return nil
	}
}

func pathfindingPassRoleTargets(g *graph.Graph, grant iamGrant) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for _, role := range passableRoles(g, grant) {
		if privilegedOrSensitiveRole(g, role) {
			out = append(out, role)
		}
	}
	return dedupeResourceIDs(out)
}

func pathfindingPrincipalTargets(g *graph.Graph, grant iamGrant, entry pathfindingCatalogEntry) []graph.ResourceID {
	candidates := matchingPrincipals(g, grant.Resources)
	if len(candidates) == 0 && resourceCovered(grant.Resources, g.Nodes[grant.Principal]) {
		candidates = append(candidates, grant.Principal)
	}
	out := make([]graph.ResourceID, 0, len(candidates))
	for _, candidate := range candidates {
		node := g.Nodes[candidate]
		if node == nil {
			continue
		}
		if !pathfindingPrincipalTargetCompatible(node, entry) {
			continue
		}
		switch {
		case entry.Category == "self-escalation" && candidate == grant.Principal:
			out = append(out, candidate)
		case pathfindingCredentialAccess(entry) && node.Type == "aws_iam_user" && (candidate == grant.Principal || privilegedOrSensitivePrincipal(g, candidate)):
			out = append(out, candidate)
		case entry.Category != "self-escalation" && privilegedOrSensitivePrincipal(g, candidate):
			out = append(out, candidate)
		}
	}
	return dedupeResourceIDs(out)
}

func pathfindingPrincipalTargetCompatible(node *graph.Node, entry pathfindingCatalogEntry) bool {
	if node == nil {
		return false
	}
	if entry.Category == "self-escalation" {
		return true
	}
	for _, action := range entry.RequiredActions {
		switch strings.ToLower(action) {
		case "iam:createaccesskey", "iam:deleteaccesskey", "iam:createloginprofile", "iam:updateloginprofile", "iam:attachuserpolicy", "iam:putuserpolicy":
			if node.Type != "aws_iam_user" {
				return false
			}
		case "iam:updaterolepolicy", "iam:updateassumerolepolicy", "iam:attachrolepolicy", "iam:putrolepolicy", "sts:assumerole":
			if node.Type != "aws_iam_role" {
				return false
			}
		}
	}
	return true
}

func pathfindingExistingResourceTargets(g *graph.Graph, grant iamGrant, entry pathfindingCatalogEntry) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for _, id := range sortedGraphNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil || !pathfindingNodeMatchesServices(node, entry.Services) || !resourceCovered(grant.Resources, node) {
			continue
		}
		for _, role := range rolesUsedBy(g, id) {
			if privilegedOrSensitiveRole(g, role) {
				out = append(out, role)
			}
		}
	}
	return dedupeResourceIDs(out)
}

func pathfindingCredentialAccess(entry pathfindingCatalogEntry) bool {
	for _, action := range entry.RequiredActions {
		action = strings.ToLower(action)
		if strings.Contains(action, "createaccesskey") || strings.Contains(action, "loginprofile") {
			return true
		}
	}
	return false
}

func pathfindingNodeMatchesServices(node *graph.Node, services []string) bool {
	if node == nil {
		return false
	}
	for _, service := range services {
		for _, prefix := range terraformTypePrefixesForService(service) {
			if strings.HasPrefix(node.Type, prefix) {
				return true
			}
		}
	}
	return false
}

func terraformTypePrefixesForService(service string) []string {
	switch strings.ToLower(service) {
	case "apprunner":
		return []string{"aws_apprunner_"}
	case "batch":
		return []string{"aws_batch_"}
	case "bedrock-agentcore", "bedrock":
		return []string{"aws_bedrock"}
	case "braket":
		return []string{"aws_braket_"}
	case "cloudformation":
		return []string{"aws_cloudformation_"}
	case "codebuild":
		return []string{"aws_codebuild_"}
	case "codedeploy":
		return []string{"aws_codedeploy_"}
	case "cognito-identity", "cognitoidentity":
		return []string{"aws_cognito_identity_"}
	case "datapipeline":
		return []string{"aws_datapipeline_"}
	case "ec2", "ec2-instance-connect":
		return []string{"aws_instance", "aws_launch_template", "aws_spot_instance_request"}
	case "ecs":
		return []string{"aws_ecs_"}
	case "elasticmapreduce", "emr":
		return []string{"aws_emr_"}
	case "emr-serverless":
		return []string{"aws_emrserverless_"}
	case "gamelift":
		return []string{"aws_gamelift_"}
	case "glue":
		return []string{"aws_glue_"}
	case "imagebuilder":
		return []string{"aws_imagebuilder_"}
	case "kinesisanalytics":
		return []string{"aws_kinesisanalytics"}
	case "lambda":
		return []string{"aws_lambda_"}
	case "omics":
		return []string{"aws_omics_"}
	case "sagemaker":
		return []string{"aws_sagemaker_"}
	case "scheduler":
		return []string{"aws_scheduler_"}
	case "ssm":
		return []string{"aws_ssm_"}
	case "states", "stepfunctions":
		return []string{"aws_sfn_", "aws_stepfunctions_"}
	default:
		normalized := strings.ReplaceAll(strings.ToLower(service), "-", "_")
		return []string{"aws_" + normalized + "_"}
	}
}

func pathfindingSteps(grant iamGrant, target graph.ResourceID, entry pathfindingCatalogEntry, confidence model.Confidence) []Step {
	steps := make([]Step, 0, len(entry.RequiredActions))
	for _, action := range entry.RequiredActions {
		steps = append(steps, iamStep(grant.Principal, target, action, graph.EdgeGrantsPermission, "principal satisfies pathfinding.cloud privilege-escalation prerequisite", confidence))
	}
	return steps
}

func pathfindingEvidence(grant iamGrant, target graph.ResourceID, entry pathfindingCatalogEntry) []model.Evidence {
	out := iamEvidence(grant, target, strings.Join(entry.RequiredActions, "+"))
	out = append(out, model.Evidence{
		Type:     "attack_path.pathfinding",
		Resource: string(target),
		Path:     "pathfinding.id",
		Value:    entry.ID,
		Message:  "Datadog pathfinding.cloud catalog path matched: " + entry.Name,
	})
	return out
}

func pathfindingMitigations(entry pathfindingCatalogEntry) []string {
	out := []string{"Remove or narrow the IAM actions required by this escalation path.", "Scope resources to exact non-privileged targets and add restrictive IAM conditions where supported."}
	if hasRequiredAction(entry, "iam:PassRole") {
		out = append(out, "Restrict iam:PassRole to approved service roles and use iam:PassedToService conditions.")
	}
	return out
}

func pathfindingReferences(entry pathfindingCatalogEntry) []string {
	refs := []string{"docs/attack-paths.md", "https://pathfinding.cloud/paths/", "https://github.com/DataDog/pathfinding.cloud"}
	refs = append(refs, entry.References...)
	return dedupeSorted(refs)
}

func hasRequiredAction(entry pathfindingCatalogEntry, action string) bool {
	for _, candidate := range entry.RequiredActions {
		if strings.EqualFold(candidate, action) {
			return true
		}
	}
	return false
}

func collectIAMGrants(g *graph.Graph) []iamGrant {
	grants := make([]iamGrant, 0)
	for _, id := range sortedGraphNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil {
			continue
		}
		if node.Kind == graph.NodePrincipal {
			grants = append(grants, grantFromObservedActions(id, node)...)
			grants = append(grants, grantsFromCloudActionEdges(g, id)...)
		}
		if node.Kind != graph.NodePolicy {
			continue
		}
		statements, ok := parsePolicyStatements(asString(node.Values["policy"]))
		if !ok {
			continue
		}
		for _, principal := range principalsForPolicyNode(g, id, node) {
			grants = append(grants, grantFromStatements(principal, id, statements))
		}
	}
	sort.SliceStable(grants, func(i int, j int) bool {
		for _, cmp := range []int{
			strings.Compare(string(grants[i].Principal), string(grants[j].Principal)),
			strings.Compare(string(grants[i].Source), string(grants[j].Source)),
		} {
			if cmp != 0 {
				return cmp < 0
			}
		}
		return false
	})
	return grants
}

func grantFromObservedActions(principal graph.ResourceID, node *graph.Node) []iamGrant {
	actions := stringSliceValue(node.Values["observed_policy_actions"])
	if len(actions) == 0 {
		return nil
	}
	return []iamGrant{{
		Principal:  principal,
		Source:     principal,
		Actions:    actions,
		Resources:  []string{"*"},
		Confidence: model.ConfidenceHigh,
	}}
}

func grantsFromCloudActionEdges(g *graph.Graph, principal graph.ResourceID) []iamGrant {
	var actions []string
	confidence := model.ConfidenceHigh
	for _, edge := range g.OutgoingEdges(principal) {
		if edge.Type != graph.EdgeGrantsPermission || !strings.HasPrefix(string(edge.To), "action:") {
			continue
		}
		actions = append(actions, strings.TrimPrefix(string(edge.To), "action:"))
		if edge.Confidence == graph.ConfidenceMedium {
			confidence = model.ConfidenceMedium
		}
		if edge.Confidence == graph.ConfidenceLow {
			confidence = model.ConfidenceLow
		}
	}
	if len(actions) == 0 {
		return nil
	}
	return []iamGrant{{
		Principal:  principal,
		Source:     principal,
		Actions:    dedupeSorted(actions),
		Resources:  []string{"*"},
		Confidence: confidence,
	}}
}

func grantFromStatements(principal graph.ResourceID, source graph.ResourceID, statements []iamStatement) iamGrant {
	grant := iamGrant{
		Principal:  principal,
		Source:     source,
		Confidence: model.ConfidenceHigh,
	}
	actions := make([]string, 0)
	notActions := make([]string, 0)
	resources := make([]string, 0)
	notResources := make([]string, 0)
	for _, statement := range statements {
		effect := strings.ToLower(statement.Effect)
		if len(statement.Condition) > 0 {
			grant.Complex = true
			grant.Confidence = model.ConfidenceMedium
		}
		if effect == "deny" {
			for _, action := range statement.Actions {
				if ActionMatches(action, "iam:PassRole") || ActionMatches(action, "sts:AssumeRole") || ActionMatches(action, "lambda:UpdateFunctionCode") || ActionMatches(action, "lambda:UpdateFunctionConfiguration") || ActionMatches(action, "lambda:CreateFunction") || ActionMatches(action, "ecs:RunTask") || ActionMatches(action, "ecs:UpdateService") || ActionMatches(action, "ecs:RegisterTaskDefinition") {
					grant.HasDeny = true
				}
			}
			if len(statement.NotActions) > 0 {
				grant.Complex = true
				grant.Confidence = model.ConfidenceMedium
			}
			continue
		}
		if effect != "allow" {
			continue
		}
		actions = append(actions, statement.Actions...)
		notActions = append(notActions, statement.NotActions...)
		resources = append(resources, statement.Resources...)
		notResources = append(notResources, statement.NotResources...)
		if len(statement.NotActions) > 0 {
			grant.BroadNotAction = true
			grant.Complex = true
			grant.Confidence = model.ConfidenceMedium
		}
		if len(statement.NotResources) > 0 {
			grant.Complex = true
			grant.Confidence = model.ConfidenceMedium
		}
	}
	grant.Actions = dedupeSorted(actions)
	grant.NotActions = dedupeSorted(notActions)
	grant.Resources = dedupeSorted(resources)
	grant.NotResources = dedupeSorted(notResources)
	if len(grant.Resources) == 0 {
		grant.Resources = []string{"*"}
	}
	if grant.HasDeny && grant.Confidence == model.ConfidenceHigh {
		grant.Confidence = model.ConfidenceMedium
	}
	return grant
}

func principalsForPolicyNode(g *graph.Graph, policy graph.ResourceID, node *graph.Node) []graph.ResourceID {
	seen := make(map[graph.ResourceID]bool)
	for _, edge := range g.IncomingEdges(policy) {
		if edge.Type == graph.EdgeAttachedTo && g.Nodes[edge.From] != nil && g.Nodes[edge.From].Kind == graph.NodePrincipal {
			seen[edge.From] = true
		}
	}
	for _, edge := range g.OutgoingEdges(policy) {
		if edge.Type == graph.EdgeGrantsPermission && g.Nodes[edge.To] != nil && g.Nodes[edge.To].Kind == graph.NodePrincipal {
			seen[edge.To] = true
		}
	}
	for _, key := range []string{"role", "user", "group"} {
		if principal := findPrincipalByName(g, asString(node.Values[key])); principal != "" {
			seen[principal] = true
		}
	}
	out := make([]graph.ResourceID, 0, len(seen))
	for principal := range seen {
		out = append(out, principal)
	}
	sort.SliceStable(out, func(i int, j int) bool { return out[i] < out[j] })
	return out
}

func parsePolicyStatements(policy string) ([]iamStatement, bool) {
	if strings.TrimSpace(policy) == "" {
		return nil, false
	}
	var raw iamDocument
	if err := json.Unmarshal([]byte(policy), &raw); err != nil {
		return nil, false
	}
	statements := rawStatements(raw.Statement)
	out := make([]iamStatement, 0, len(statements))
	for _, statement := range statements {
		out = append(out, iamStatement{
			Effect:       asString(statement["Effect"]),
			Actions:      policyStringList(statement["Action"]),
			NotActions:   policyStringList(statement["NotAction"]),
			Resources:    policyStringList(statement["Resource"]),
			NotResources: policyStringList(statement["NotResource"]),
			Condition:    policyMap(statement["Condition"]),
		})
	}
	return out, true
}

func rawStatements(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if statement, ok := item.(map[string]any); ok {
				out = append(out, statement)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{typed}
	default:
		return nil
	}
}

func policyStringList(value any) []string {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := asString(item)
			if text != "" {
				out = append(out, text)
			}
		}
		return dedupeSorted(out)
	case []string:
		return dedupeSorted(typed)
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func policyMap(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func grantAllows(grant iamGrant, action string) bool {
	if grant.HasDeny && grant.Confidence == model.ConfidenceHigh {
		return false
	}
	for _, pattern := range grant.Actions {
		if ActionMatches(pattern, action) {
			return true
		}
	}
	if grant.BroadNotAction {
		for _, excluded := range grant.NotActions {
			if ActionMatches(excluded, action) {
				return false
			}
		}
		return true
	}
	return false
}

func grantAllowsAll(grant iamGrant, actions ...string) bool {
	for _, action := range actions {
		if !grantAllows(grant, action) {
			return false
		}
	}
	return true
}

func firstAllowedAction(grant iamGrant, actions ...string) string {
	for _, action := range actions {
		if grantAllows(grant, action) {
			return action
		}
	}
	return ""
}

func passableRoles(g *graph.Graph, grant iamGrant) []graph.ResourceID {
	return matchingRoles(g, grant.Resources)
}

func assumableRoles(g *graph.Graph, grant iamGrant) []graph.ResourceID {
	return matchingRoles(g, grant.Resources)
}

func matchingRoles(g *graph.Graph, resources []string) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for _, id := range sortedGraphNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil || node.Type != "aws_iam_role" {
			continue
		}
		if resourceCovered(resources, node) {
			out = append(out, id)
		}
	}
	return out
}

func matchingPrincipals(g *graph.Graph, resources []string) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for _, id := range sortedGraphNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil || node.Kind != graph.NodePrincipal {
			continue
		}
		if resourceCovered(resources, node) {
			out = append(out, id)
		}
	}
	return out
}

func resourceCovered(resources []string, node *graph.Node) bool {
	if node == nil || len(resources) == 0 {
		return false
	}
	for _, resource := range resources {
		resource = strings.TrimSpace(resource)
		if resource == "*" || resource == "" {
			return true
		}
		for _, candidate := range resourceCandidates(node) {
			if candidate == "" {
				continue
			}
			if resource == candidate || strings.HasSuffix(resource, ":"+candidate) || strings.Contains(resource, candidate) || strings.Contains(candidate, resource) {
				return true
			}
		}
	}
	return false
}

func resourceCandidates(node *graph.Node) []string {
	return []string{
		string(node.ID),
		node.Address,
		node.Name,
		asString(node.Values["arn"]),
		asString(node.Values["id"]),
	}
}

func privilegedOrSensitiveRole(g *graph.Graph, role graph.ResourceID) bool {
	return adminRole(g, role) || sensitiveRole(g, role)
}

func adminRole(g *graph.Graph, role graph.ResourceID) bool {
	node := g.Nodes[role]
	if node == nil || node.Type != "aws_iam_role" {
		return false
	}
	lower := strings.ToLower(string(role) + " " + node.Address + " " + node.Name + " " + asString(node.Values["arn"]))
	if strings.Contains(lower, "admin") || strings.Contains(lower, "administrator") {
		return true
	}
	for _, action := range stringSliceValue(node.Values["observed_policy_actions"]) {
		if ActionMatches(action, "*") || ActionMatches(action, "iam:*") || ActionMatches(action, "sts:*") {
			return true
		}
	}
	for _, edge := range g.OutgoingEdges(role) {
		if edge.Type == graph.EdgeGrantsPermission && (edge.To == "action:*" || edge.To == "action:iam:*") {
			return true
		}
	}
	return false
}

func sensitiveRole(g *graph.Graph, role graph.ResourceID) bool {
	for _, edge := range g.OutgoingEdges(role) {
		if edge.Type == graph.EdgeCanReadData || edge.Type == graph.EdgeCanWriteData || edge.Type == graph.EdgeReadsSecret || edge.Type == graph.EdgeWritesTo {
			if node := g.Nodes[edge.To]; node != nil && (node.Kind == graph.NodeDataStore || node.Kind == graph.NodeSecret || node.Kind == graph.NodeKMSKey) {
				return true
			}
		}
	}
	return false
}

func privilegedOrSensitivePrincipal(g *graph.Graph, id graph.ResourceID) bool {
	node := g.Nodes[id]
	if node == nil || node.Kind != graph.NodePrincipal {
		return false
	}
	if node.Type == "aws_iam_role" {
		return privilegedOrSensitiveRole(g, id)
	}
	lower := strings.ToLower(string(id) + " " + node.Address + " " + node.Name + " " + asString(node.Values["arn"]))
	return strings.Contains(lower, "admin") || strings.Contains(lower, "administrator")
}

func escalationTargets(g *graph.Graph, grant iamGrant, pattern iamEscalationPattern) []graph.ResourceID {
	candidates := matchingPrincipals(g, grant.Resources)
	if len(candidates) == 0 && resourceCovered(grant.Resources, g.Nodes[grant.Principal]) {
		candidates = append(candidates, grant.Principal)
	}
	out := make([]graph.ResourceID, 0, len(candidates))
	for _, candidate := range candidates {
		node := g.Nodes[candidate]
		if node == nil {
			continue
		}
		if strings.Contains(pattern.ID, "access_key") && node.Type != "aws_iam_user" {
			continue
		}
		if privilegedOrSensitivePrincipal(g, candidate) || candidate == grant.Principal {
			out = append(out, candidate)
		}
	}
	sort.SliceStable(out, func(i int, j int) bool { return out[i] < out[j] })
	return dedupeResourceIDs(out)
}

func dedupeResourceIDs(values []graph.ResourceID) []graph.ResourceID {
	seen := make(map[graph.ResourceID]bool, len(values))
	out := make([]graph.ResourceID, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func rolesUsedBy(g *graph.Graph, workload graph.ResourceID) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for _, edge := range g.OutgoingEdges(workload) {
		if (edge.Type == graph.EdgeCanAssume || edge.Type == graph.EdgeCanPassRole || edge.Type == graph.EdgeAttachedTo) && g.Nodes[edge.To] != nil && g.Nodes[edge.To].Type == "aws_iam_role" {
			out = append(out, edge.To)
		}
	}
	sort.SliceStable(out, func(i int, j int) bool { return out[i] < out[j] })
	return out
}

func ecsServiceRoles(g *graph.Graph, service graph.ResourceID) []graph.ResourceID {
	seen := make(map[graph.ResourceID]bool)
	for _, edge := range g.OutgoingEdges(service) {
		if edge.Type != graph.EdgeDependsOn && edge.Type != graph.EdgeAttachedTo {
			continue
		}
		for _, role := range rolesUsedBy(g, edge.To) {
			seen[role] = true
		}
	}
	for _, role := range rolesUsedBy(g, service) {
		seen[role] = true
	}
	out := make([]graph.ResourceID, 0, len(seen))
	for role := range seen {
		out = append(out, role)
	}
	sort.SliceStable(out, func(i int, j int) bool { return out[i] < out[j] })
	return out
}

func iamDecisionForTarget(target *graph.Node, grant iamGrant) (model.Decision, model.Severity, model.Confidence) {
	confidence := grant.Confidence
	if grant.Complex || grant.HasDeny {
		confidence = model.ConfidenceMedium
	}
	decision, severity := iamDecision(confidence, target)
	return decision, severity, confidence
}

func iamDecision(confidence model.Confidence, target *graph.Node) (model.Decision, model.Severity) {
	if confidence != model.ConfidenceHigh {
		return model.DecisionWarn, model.SeverityHigh
	}
	if target != nil && target.Environment == "production" {
		return model.DecisionBlock, model.SeverityCritical
	}
	return model.DecisionBlock, model.SeverityHigh
}

func confidenceFromGraph(confidence graph.EdgeConfidence, source graph.EdgeSource) model.Confidence {
	switch confidence {
	case graph.ConfidenceLow:
		return model.ConfidenceLow
	case graph.ConfidenceMedium:
		return model.ConfidenceMedium
	default:
		if source == graph.SourceInferred {
			return model.ConfidenceMedium
		}
		return model.ConfidenceHigh
	}
}

func iamStep(from graph.ResourceID, to graph.ResourceID, action string, edgeType graph.EdgeType, explanation string, confidence model.Confidence) Step {
	edgeConfidence := graph.ConfidenceHigh
	if confidence == model.ConfidenceMedium {
		edgeConfidence = graph.ConfidenceMedium
	}
	if confidence == model.ConfidenceLow {
		edgeConfidence = graph.ConfidenceLow
	}
	return Step{
		From:        string(from),
		To:          string(to),
		Action:      action,
		EdgeType:    edgeType,
		Source:      graph.SourcePlan,
		Confidence:  edgeConfidence,
		Explanation: explanation,
	}
}

func iamGraphStep(from graph.ResourceID, to graph.ResourceID, action string, edgeType graph.EdgeType, explanation string, edge graph.Edge) Step {
	return Step{
		From:        string(from),
		To:          string(to),
		Action:      action,
		EdgeType:    edgeType,
		Source:      edge.Source,
		Confidence:  edge.Confidence,
		Explanation: explanation,
		Evidence:    append([]model.Evidence(nil), edge.Evidence...),
		Metadata:    copyStepMetadata(edge.Metadata),
	}
}

func iamConfidenceReason(confidence model.Confidence, grant iamGrant, reason string) string {
	switch {
	case grant.BroadNotAction:
		return "medium confidence: broad IAM NotAction allow implies the required permissions unless excluded, so ChangeGate warns instead of treating it as exact evidence"
	case grant.Complex || grant.HasDeny || confidence != model.ConfidenceHigh:
		return "medium confidence: " + reason + ", but policy conditions, deny statements, or broad resource semantics require reviewer confirmation"
	default:
		return "high confidence: " + reason + " with explicit IAM policy evidence and no contradicting deny statement"
	}
}

func iamGraphConfidenceReason(confidence model.Confidence, reason string) string {
	if confidence != model.ConfidenceHigh {
		return "medium confidence: " + reason + ", but at least one graph relationship is inferred or partial"
	}
	return "high confidence: " + reason + " with explicit graph evidence for every step"
}

func iamMetadata(grant iamGrant, metadata map[string]string) map[string]string {
	out := copyMetadata(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if grant.BroadNotAction {
		out["iam_semantics"] = "not_action_broad_allow"
	}
	if grant.Complex {
		out["iam_complexity"] = "conditions_or_negative_semantics"
	}
	if grant.HasDeny {
		out["iam_deny"] = "present"
	}
	return out
}

func iamEvidence(grant iamGrant, target graph.ResourceID, action string) []model.Evidence {
	return []model.Evidence{{
		Type:     "attack_path.iam",
		Resource: string(target),
		Path:     "iam.policy",
		Value:    []string{string(grant.Principal), action, string(target)},
		Message:  fmt.Sprintf("principal has %s through %s", action, grant.Source),
	}}
}

func edgeExplanationFromGraph(edge graph.Edge) string {
	for _, evidence := range edge.Evidence {
		if evidence.Message != "" {
			return evidence.Message
		}
	}
	return "principal can assume role"
}

func mutationTarget(action string) graph.ResourceID {
	switch strings.ToLower(action) {
	case "lambda:updatefunctioncode":
		return "aws_lambda_function.*"
	case "lambda:updatefunctionconfiguration":
		return "aws_lambda_function.*"
	case "lambda:createfunction":
		return "aws_lambda_function.*"
	case "ecs:runtask":
		return "aws_ecs_task_definition.*"
	case "ecs:updateservice":
		return "aws_ecs_service.*"
	case "ecs:registertaskdefinition":
		return "aws_ecs_task_definition.*"
	default:
		return graph.ResourceID(action)
	}
}

func roleAssumptionGraphPaths(g *graph.Graph, start graph.ResourceID, maxDepth int) []graph.Path {
	if maxDepth <= 0 {
		maxDepth = 4
	}
	type item struct {
		id    graph.ResourceID
		path  graph.Path
		seen  map[graph.ResourceID]bool
		depth int
	}
	queue := []item{{id: start, path: graph.Path{Nodes: []graph.ResourceID{start}}, seen: map[graph.ResourceID]bool{start: true}}}
	out := make([]graph.Path, 0)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= maxDepth {
			continue
		}
		for _, edge := range g.OutgoingEdges(current.id) {
			if edge.Type != graph.EdgeCanAssume || current.seen[edge.To] {
				continue
			}
			nextPath := graph.Path{
				Nodes: append(append([]graph.ResourceID(nil), current.path.Nodes...), edge.To),
				Edges: append(append([]graph.Edge(nil), current.path.Edges...), edge),
			}
			nextSeen := make(map[graph.ResourceID]bool, len(current.seen)+1)
			for key, value := range current.seen {
				nextSeen[key] = value
			}
			nextSeen[edge.To] = true
			if len(nextPath.Edges) >= 2 {
				out = append(out, nextPath)
			}
			queue = append(queue, item{id: edge.To, path: nextPath, seen: nextSeen, depth: current.depth + 1})
		}
	}
	return out
}

func graphPathNodes(path graph.Path) []string {
	out := make([]string, 0, len(path.Nodes))
	for _, node := range path.Nodes {
		out = append(out, string(node))
	}
	return out
}

func sortedNodesByKind(g *graph.Graph, kind graph.NodeKind) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for _, id := range sortedGraphNodeIDs(g) {
		if node := g.Nodes[id]; node != nil && node.Kind == kind {
			out = append(out, id)
		}
	}
	return out
}

func sortedGraphNodeIDs(g *graph.Graph) []graph.ResourceID {
	out := make([]graph.ResourceID, 0, len(g.Nodes))
	for id := range g.Nodes {
		out = append(out, id)
	}
	sort.SliceStable(out, func(i int, j int) bool { return out[i] < out[j] })
	return out
}

func findPrincipalByName(g *graph.Graph, name string) graph.ResourceID {
	if name == "" || name == "<nil>" {
		return ""
	}
	for _, id := range sortedGraphNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil || node.Kind != graph.NodePrincipal {
			continue
		}
		if string(id) == name || node.Address == name || node.Name == name || strings.HasSuffix(string(id), "."+name) || asString(node.Values["id"]) == name || asString(node.Values["arn"]) == name {
			return id
		}
	}
	return ""
}

func stringSliceValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return dedupeSorted(typed)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := asString(item)
			if text != "" {
				out = append(out, text)
			}
		}
		return dedupeSorted(out)
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprint(value)
	}
}
