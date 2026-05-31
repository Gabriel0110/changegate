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
	Principal  graph.ResourceID
	Source     graph.ResourceID
	Actions    []string
	Resources  []string
	Confidence model.Confidence
	HasDeny    bool
	Complex    bool
}

type iamDocument struct {
	Statement any `json:"Statement"`
}

type iamStatement struct {
	Effect    string
	Actions   []string
	Resources []string
	Condition map[string]any
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
	paths = append(paths, detectFunctionUpdateRoleAccess(g, grants, opts)...)
	paths = append(paths, detectECSUpdateServiceRoleAccess(g, grants, opts)...)
	return Normalize(paths)
}

func detectPassRoleComputeMutation(g *graph.Graph, grants []iamGrant, opts IAMDetectionOptions) []AttackPath {
	out := make([]AttackPath, 0)
	for _, grant := range grants {
		if !grantAllows(grant, "iam:PassRole") {
			continue
		}
		mutation := firstAllowedAction(grant, "lambda:UpdateFunctionCode", "ecs:RunTask")
		if mutation == "" {
			continue
		}
		for _, role := range passableRoles(g, grant) {
			decision, severity, confidence := iamDecisionForTarget(g.Nodes[role], grant)
			if decision == model.DecisionWarn && !opts.IncludeWarnings {
				continue
			}
			out = append(out, AttackPath{
				Type:       TypeIAMPrivilegeEscalation,
				Title:      fmt.Sprintf("Principal %s can pass %s and run %s", grant.Principal, role, mutation),
				Severity:   severity,
				Confidence: confidence,
				Decision:   decision,
				Principal:  string(grant.Principal),
				Target:     string(role),
				Steps: []Step{
					iamStep(grant.Principal, role, "iam:PassRole", graph.EdgeCanPassRole, "principal can pass a privileged or sensitive execution role"),
					iamStep(grant.Principal, mutationTarget(mutation), mutation, graph.EdgeGrantsPermission, "principal can mutate or launch compute that can use the passed role"),
				},
				Evidence:    iamEvidence(grant, role, mutation),
				Mitigations: []string{"Scope iam:PassRole to non-privileged execution roles and exact services.", "Separate compute mutation permissions from pass-role permissions."},
				References:  []string{"https://changegate.dev/docs/attack-paths"},
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
			Type:       TypeIAMPrivilegeEscalation,
			Title:      fmt.Sprintf("Principal %s can assume privileged role %s", edge.From, edge.To),
			Severity:   severity,
			Confidence: confidence,
			Decision:   decision,
			Principal:  string(edge.From),
			Target:     string(edge.To),
			Steps:      []Step{iamStep(edge.From, edge.To, "sts:AssumeRole", graph.EdgeCanAssume, edgeExplanationFromGraph(edge))},
			Evidence: []model.Evidence{{
				Type:     "attack_path.iam",
				Resource: string(edge.To),
				Path:     "graph.can_assume",
				Value:    []string{string(edge.From), string(edge.To)},
				Message:  "principal can assume a privileged or sensitive role",
			}},
			Mitigations: []string{"Remove broad trust or require tightly scoped conditions and approval for privileged role assumption."},
			References:  []string{"https://changegate.dev/docs/attack-paths"},
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
				Type:        TypeIAMPrivilegeEscalation,
				Title:       fmt.Sprintf("Principal %s can assume privileged role %s", grant.Principal, role),
				Severity:    severity,
				Confidence:  confidence,
				Decision:    decision,
				Principal:   string(grant.Principal),
				Target:      string(role),
				Steps:       []Step{iamStep(grant.Principal, role, "sts:AssumeRole", graph.EdgeCanAssume, "policy allows role assumption")},
				Evidence:    iamEvidence(grant, role, "sts:AssumeRole"),
				Mitigations: []string{"Scope sts:AssumeRole to exact non-admin roles and require restrictive trust conditions."},
				References:  []string{"https://changegate.dev/docs/attack-paths"},
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
					Type:       TypeIAMPrivilegeEscalation,
					Title:      fmt.Sprintf("Principal %s can update Lambda %s with privileged execution role", grant.Principal, fn),
					Severity:   severity,
					Confidence: confidence,
					Decision:   decision,
					Principal:  string(grant.Principal),
					Target:     string(role),
					Steps: []Step{
						iamStep(grant.Principal, fn, "lambda:UpdateFunctionCode", graph.EdgeGrantsPermission, "principal can update executable Lambda code"),
						iamStep(fn, role, "uses execution role", graph.EdgeCanAssume, "function executes with privileged or sensitive role access"),
					},
					Evidence:    iamEvidence(grant, role, "lambda:UpdateFunctionCode"),
					Mitigations: []string{"Remove function update access or move the function to a least-privilege execution role."},
					References:  []string{"https://changegate.dev/docs/attack-paths"},
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
					Type:       TypeIAMPrivilegeEscalation,
					Title:      fmt.Sprintf("Principal %s can update ECS service %s with sensitive task role", grant.Principal, service),
					Severity:   severity,
					Confidence: confidence,
					Decision:   decision,
					Principal:  string(grant.Principal),
					Target:     string(role),
					Steps: []Step{
						iamStep(grant.Principal, service, "ecs:UpdateService", graph.EdgeGrantsPermission, "principal can update service task execution"),
						iamStep(service, role, "uses task role", graph.EdgeCanPassRole, "service task role can access sensitive data or secrets"),
					},
					Evidence:    iamEvidence(grant, role, "ecs:UpdateService"),
					Mitigations: []string{"Remove service update access or use a task role without sensitive data access."},
					References:  []string{"https://changegate.dev/docs/attack-paths"},
				})
			}
		}
	}
	return out
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
	resources := make([]string, 0)
	for _, statement := range statements {
		effect := strings.ToLower(statement.Effect)
		if len(statement.Condition) > 0 {
			grant.Complex = true
			grant.Confidence = model.ConfidenceMedium
		}
		if effect == "deny" {
			for _, action := range statement.Actions {
				if ActionMatches(action, "iam:PassRole") || ActionMatches(action, "sts:AssumeRole") || ActionMatches(action, "lambda:UpdateFunctionCode") || ActionMatches(action, "ecs:RunTask") || ActionMatches(action, "ecs:UpdateService") {
					grant.HasDeny = true
				}
			}
			continue
		}
		if effect != "allow" {
			continue
		}
		actions = append(actions, statement.Actions...)
		resources = append(resources, statement.Resources...)
	}
	grant.Actions = dedupeSorted(actions)
	grant.Resources = dedupeSorted(resources)
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
			Effect:    asString(statement["Effect"]),
			Actions:   policyStringList(firstPresent(statement, "Action", "NotAction")),
			Resources: policyStringList(firstPresent(statement, "Resource", "NotResource")),
			Condition: policyMap(statement["Condition"]),
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

func firstPresent(values map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value
		}
	}
	return nil
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
	return false
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

func iamStep(from graph.ResourceID, to graph.ResourceID, action string, edgeType graph.EdgeType, explanation string) Step {
	return Step{
		From:        string(from),
		To:          string(to),
		Action:      action,
		EdgeType:    edgeType,
		Explanation: explanation,
	}
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
	case "ecs:runtask":
		return "aws_ecs_task_definition.*"
	default:
		return graph.ResourceID(action)
	}
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
