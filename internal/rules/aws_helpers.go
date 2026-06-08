package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func sortedChanges(plan *model.Plan) []model.Change {
	if plan == nil {
		return nil
	}
	out := append([]model.Change(nil), plan.Changes...)
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].Address < out[j].Address
	})
	return out
}

func sortedNodes(g *graph.Graph) map[graph.ResourceID]*graph.Node {
	if g == nil {
		return nil
	}
	return g.Nodes
}

func ev(resource string, path string, value any, message string) model.Evidence {
	return model.Evidence{
		Type:     "rule",
		Resource: resource,
		Path:     path,
		Value:    value,
		Message:  message,
	}
}

func exposureEvidence(g *graph.Graph, from graph.ResourceID, to graph.ResourceID, resource string) []model.Evidence {
	if g == nil {
		return []model.Evidence{ev(resource, "graph", to, "resource is internet exposed")}
	}
	lines, ok := g.ExplainConnection(from, to)
	if !ok || len(lines) == 0 {
		return []model.Evidence{ev(resource, "graph", to, "resource is internet exposed")}
	}
	out := make([]model.Evidence, 0, len(lines))
	for _, line := range lines {
		out = append(out, ev(resource, "graph", to, line))
	}
	return out
}

func firstHighConfidencePath(g *graph.Graph, from graph.ResourceID, to graph.ResourceID) (graph.Path, bool) {
	if g == nil {
		return graph.Path{}, false
	}
	if from == to {
		return graph.Path{Nodes: []graph.ResourceID{from}}, true
	}
	paths := g.Paths(from, to, graph.PathOptions{
		MaxDepth: 12,
		MaxPaths: 1,
		AllowedEdges: []graph.EdgeType{
			graph.EdgeRoutesTo,
			graph.EdgeInvokes,
			graph.EdgeAllowsIngress,
			graph.EdgeAllowsEgress,
			graph.EdgeAttachedTo,
			graph.EdgeContainedIn,
			graph.EdgeCanReadData,
			graph.EdgeCanWriteData,
			graph.EdgeReadsSecret,
			graph.EdgeWritesTo,
		},
	})
	if len(paths) == 0 || !highConfidencePath(paths[0]) {
		return graph.Path{}, false
	}
	return paths[0], true
}

func firstHighConfidenceSensitiveCapabilityPath(g *graph.Graph, from graph.ResourceID, to graph.ResourceID) (graph.Path, bool) {
	if g == nil {
		return graph.Path{}, false
	}
	if from == to {
		return graph.Path{Nodes: []graph.ResourceID{from}}, true
	}
	paths := g.Paths(from, to, graph.PathOptions{
		MaxDepth: 14,
		MaxPaths: 1,
		AllowedEdges: []graph.EdgeType{
			graph.EdgeRoutesTo,
			graph.EdgeInvokes,
			graph.EdgeAllowsIngress,
			graph.EdgeAllowsEgress,
			graph.EdgeAttachedTo,
			graph.EdgeContainedIn,
			graph.EdgeDependsOn,
			graph.EdgeCanAssume,
			graph.EdgeCanPassRole,
			graph.EdgeGrantsPermission,
			graph.EdgeCanReadData,
			graph.EdgeCanWriteData,
			graph.EdgeReadsSecret,
			graph.EdgeEncryptsWith,
			graph.EdgeWritesTo,
		},
	})
	if len(paths) == 0 || !highConfidencePath(paths[0]) {
		return graph.Path{}, false
	}
	return paths[0], true
}

func highConfidencePath(path graph.Path) bool {
	for _, edge := range path.Edges {
		if edge.Confidence != "" && edge.Confidence != graph.ConfidenceHigh {
			return false
		}
	}
	return true
}

func pathHasWorkload(g *graph.Graph, path graph.Path) bool {
	if g == nil {
		return false
	}
	for _, id := range path.Nodes {
		if node := g.Nodes[id]; node != nil && node.Kind == graph.NodeWorkload {
			return true
		}
	}
	return false
}

func pathContainsEdge(path graph.Path, types ...graph.EdgeType) bool {
	allowed := make(map[graph.EdgeType]bool, len(types))
	for _, typ := range types {
		allowed[typ] = true
	}
	for _, edge := range path.Edges {
		if allowed[edge.Type] {
			return true
		}
	}
	return false
}

func graphPathEvidence(resource string, target string, path graph.Path) []model.Evidence {
	nodes := make([]string, 0, len(path.Nodes))
	for _, node := range path.Nodes {
		nodes = append(nodes, string(node))
	}
	out := []model.Evidence{
		ev(resource, "graph.path", nodes, "public resource has a high-confidence graph path to sensitive datastore"),
		ev(target, "graph.target", target, "sensitive datastore is reachable from public resource"),
	}
	for _, edge := range path.Edges {
		for _, evidence := range edge.Evidence {
			if evidence.Message != "" {
				out = append(out, ev(resource, "graph.edge", []string{string(edge.From), string(edge.To), string(edge.Type)}, evidence.Message))
				break
			}
		}
	}
	return out
}

func sensitiveGraphPathEvidence(resource string, target string, path graph.Path, message string) []model.Evidence {
	nodes := make([]string, 0, len(path.Nodes))
	for _, node := range path.Nodes {
		nodes = append(nodes, string(node))
	}
	out := []model.Evidence{
		ev(resource, "graph.path", nodes, message),
		ev(target, "graph.target", target, "sensitive graph target is reachable from public infrastructure"),
	}
	for _, edge := range path.Edges {
		for _, evidence := range edge.Evidence {
			if evidence.Message != "" {
				out = append(out, ev(resource, "graph.edge", []string{string(edge.From), string(edge.To), string(edge.Type)}, evidence.Message))
				break
			}
		}
	}
	return out
}

func publicEntrypointToSensitiveDataFindings(input RuleInput, meta Metadata, entrypointTypes map[string]bool, include func(graph.ResourceID, *graph.Node) bool, message string, remediation string) []model.Finding {
	if input.Graph == nil {
		return nil
	}
	out := make([]model.Finding, 0)
	seen := make(map[string]bool)
	for entryID, entrypoint := range sortedNodes(input.Graph) {
		if entrypoint == nil || !entrypointTypes[entrypoint.Type] {
			continue
		}
		if include != nil && !include(entryID, entrypoint) {
			continue
		}
		if entrypoint.Kind != graph.NodePublicEntrypoint && !input.Graph.IsInternetExposed(entryID) {
			continue
		}
		for targetID, target := range sortedNodes(input.Graph) {
			if entryID == targetID || !isSensitiveNode(target) {
				continue
			}
			path, ok := firstHighConfidenceSensitiveCapabilityPath(input.Graph, entryID, targetID)
			if !ok || !pathHasWorkload(input.Graph, path) {
				continue
			}
			key := string(entryID) + "=>" + string(targetID)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, finding(meta, entrypoint.Address, entrypoint.Provider, entrypoint.Environment, sensitiveGraphPathEvidence(entrypoint.Address, target.Address, path, message), remediation))
		}
	}
	return out
}

func unauthenticatedAPIGatewayKeys(plan *model.Plan) map[string]bool {
	out := make(map[string]bool)
	record := func(resourceType string, values map[string]any, address string, name string) {
		switch resourceType {
		case "aws_apigatewayv2_route":
			auth := strings.ToLower(asString(values["authorization_type"]))
			if auth != "" && auth != "none" {
				return
			}
			addNonEmptyKeys(out, asString(values["api_id"]), address, name)
		case "aws_api_gateway_method":
			auth := strings.ToLower(asString(values["authorization"]))
			if auth != "" && auth != "none" {
				return
			}
			addNonEmptyKeys(out, asString(values["rest_api_id"]), address, name)
		}
	}
	for _, change := range sortedChanges(plan) {
		record(change.Type, change.After, change.Address, change.Name)
	}
	if plan != nil {
		for _, resource := range plan.Resources {
			record(resource.Type, resource.Values, resource.Address, resource.Name)
		}
	}
	return out
}

func matchesGraphNodeKey(node *graph.Node, keys map[string]bool) bool {
	if node == nil {
		return false
	}
	return keys[string(node.ID)] || keys[node.Address] || keys[node.Name] || keys[asString(node.Values["id"])] || keys[asString(node.Values["name"])]
}

func addNonEmptyKeys(keys map[string]bool, values ...string) {
	for _, value := range values {
		if value != "" {
			keys[value] = true
		}
	}
}

func publicWorkloadSensitiveFindings(input RuleInput, meta Metadata, match func(workload *graph.Node, target *graph.Node, path graph.Path) bool, message string, remediation string) []model.Finding {
	if input.Graph == nil {
		return nil
	}
	out := make([]model.Finding, 0)
	seen := make(map[string]bool)
	for workloadID, workload := range sortedNodes(input.Graph) {
		if workload == nil || workload.Kind != graph.NodeWorkload || !hasHighConfidencePublicWorkloadExposure(input, workloadID) {
			continue
		}
		for targetID, target := range sortedNodes(input.Graph) {
			if workloadID == targetID || target == nil {
				continue
			}
			path, ok := firstHighConfidenceSensitiveCapabilityPath(input.Graph, workloadID, targetID)
			if !ok || !match(workload, target, path) {
				continue
			}
			key := string(workloadID) + "=>" + string(targetID)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, finding(meta, workload.Address, workload.Provider, workload.Environment, sensitiveGraphPathEvidence(workload.Address, target.Address, path, message), remediation))
		}
	}
	return out
}

func hasHighConfidencePublicWorkloadExposure(input RuleInput, workloadID graph.ResourceID) bool {
	if input.Graph == nil {
		return false
	}
	paths := input.Graph.Paths(graph.InternetNodeID, workloadID, graph.PathOptions{
		MaxDepth: 10,
		MaxPaths: 5,
		AllowedEdges: []graph.EdgeType{
			graph.EdgeRoutesTo,
			graph.EdgeInvokes,
			graph.EdgeAllowsIngress,
			graph.EdgeAttachedTo,
			graph.EdgeContainedIn,
		},
	})
	if len(paths) == 0 {
		return false
	}
	unauthenticatedAPIs := unauthenticatedAPIGatewayKeys(input.Plan)
	for _, path := range paths {
		if !highConfidencePath(path) {
			continue
		}
		if pathRequiresAuthenticatedAPI(input.Graph, path, unauthenticatedAPIs) {
			continue
		}
		return true
	}
	return false
}

func pathRequiresAuthenticatedAPI(g *graph.Graph, path graph.Path, unauthenticatedAPIs map[string]bool) bool {
	if g == nil {
		return false
	}
	for _, nodeID := range path.Nodes {
		node := g.Nodes[nodeID]
		if node == nil || !apiGatewayNodeType(node.Type) {
			continue
		}
		if !matchesGraphNodeKey(node, unauthenticatedAPIs) {
			return true
		}
	}
	return false
}

func apiGatewayNodeType(resourceType string) bool {
	switch resourceType {
	case "aws_api_gateway_rest_api", "aws_apigatewayv2_api", "aws_api_gateway_stage", "aws_apigatewayv2_stage":
		return true
	default:
		return false
	}
}

func looksAdmin(node *graph.Node) bool {
	if node == nil {
		return false
	}
	text := strings.ToLower(node.Address + " " + node.Name + " " + node.Tags["service"] + " " + node.Tags["role"])
	return strings.Contains(text, "admin") || strings.Contains(text, "backoffice") || strings.Contains(text, "console")
}

func isInternal(node *graph.Node) bool {
	if node == nil {
		return false
	}
	for _, key := range []string{"exposure", "visibility", "tier", "service"} {
		if strings.EqualFold(node.Tags[key], "internal") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(node.Address), "internal")
}

func adminPorts() map[int]bool {
	return map[int]bool{22: true, 3389: true, 5432: true, 3306: true, 6379: true, 9200: true, 9300: true, 6443: true}
}

func dbPorts() map[int]bool {
	return map[int]bool{5432: true, 3306: true, 1433: true, 1521: true, 27017: true, 6379: true, 9042: true}
}

func securityGroupPortFindings(input RuleInput, meta Metadata, ports map[int]bool, message string, remediation string) []model.Finding {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_security_group" && change.Type != "aws_vpc_security_group_ingress_rule" {
			continue
		}
		if !publicCIDRInChange(change) {
			continue
		}
		if !portsTouched(change, ports) {
			continue
		}
		out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{
			ev(change.Address, "ingress", "0.0.0.0/0", message),
		}, remediation))
	}
	return out
}

func publicCIDRInChange(change model.Change) bool {
	text := asJSON(change.After)
	return strings.Contains(text, "0.0.0.0/0") || strings.Contains(text, "::/0")
}

func rulePublicCIDR(rule map[string]any) bool {
	if cidrIsPublicValue(rule["cidr_ipv4"]) || cidrIsPublicValue(rule["cidr_ipv6"]) {
		return true
	}
	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		for _, value := range asList(rule[key]) {
			if cidrIsPublicValue(value) {
				return true
			}
		}
	}
	return false
}

func cidrIsPublicValue(value any) bool {
	text := asString(value)
	return text == "0.0.0.0/0" || text == "::/0"
}

func allPortsRule(rule map[string]any) bool {
	protocol := strings.ToLower(asString(firstNonEmpty(rule["protocol"], rule["ip_protocol"])))
	if protocol == "-1" || protocol == "all" {
		return true
	}
	from, hasFrom := optionalInt(rule["from_port"])
	to, hasTo := optionalInt(rule["to_port"])
	if !hasFrom || !hasTo {
		return false
	}
	return from <= 0 && (to == 0 || to >= 65535)
}

func firstNonEmpty(values ...any) any {
	for _, value := range values {
		if asString(value) != "" {
			return value
		}
	}
	return nil
}

func optionalInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		out, err := typed.Int64()
		return int(out), err == nil
	case string:
		if typed == "" {
			return 0, false
		}
		out, err := strconv.Atoi(typed)
		return out, err == nil
	default:
		return 0, false
	}
}

func portsTouched(change model.Change, ports map[int]bool) bool {
	for _, key := range []string{"from_port", "to_port"} {
		if ports[intValue(change.After[key])] {
			return true
		}
	}
	text := asJSON(change.After)
	for port := range ports {
		if strings.Contains(text, strconv.Itoa(port)) {
			return true
		}
	}
	return false
}

func envFromChange(change model.Change) string {
	for _, key := range []string{"env", "environment", "stage"} {
		value := strings.ToLower(change.Tags[key])
		if value == "" {
			if tags, ok := change.After["tags"].(map[string]any); ok {
				value = strings.ToLower(asString(tags[key]))
			}
		}
		switch value {
		case "prod", "production":
			return "production"
		case "stage", "staging":
			return "staging"
		case "dev", "development":
			return "development"
		}
	}
	return ""
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := asString(item)
			if text != "" && text != "<nil>" {
				out = append(out, text)
			}
		}
		sort.Strings(out)
		return out
	case []string:
		out := append([]string(nil), typed...)
		sort.Strings(out)
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func asList(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case nil:
		return nil
	default:
		return []any{typed}
	}
}

func truthy(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func falsey(value any) bool {
	switch typed := value.(type) {
	case bool:
		return !typed
	case string:
		return strings.EqualFold(typed, "false") || strings.EqualFold(typed, "disabled") || strings.EqualFold(typed, "suspended")
	case nil:
		return true
	default:
		return false
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		out, _ := typed.Int64()
		return int(out)
	case string:
		out, _ := strconv.Atoi(typed)
		return out
	default:
		return 0
	}
}

func hasAction(change model.Change, action model.Action) bool {
	for _, candidate := range change.Actions {
		if candidate == action {
			return true
		}
	}
	return false
}

func asJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return strings.ToLower(string(encoded))
}

func normalizedChangeText(change model.Change) string {
	return strings.ToLower(change.Address + " " + change.Name + " " + fmt.Sprint(change.Tags) + " " + asJSON(change.After) + " " + asJSON(change.Before))
}

func hasProductionOrSensitiveContext(change model.Change) bool {
	if envFromChange(change) == "production" {
		return true
	}
	text := normalizedChangeText(change)
	for _, marker := range []string{"prod", "production", "sensitive", "customer", "payment", "pii", "secret", "backup", "audit", "security"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

type s3BucketContext struct {
	Address string
	Name    string
	Bucket  string
	Keys    []string
}

type s3BucketIndex struct {
	buckets                    map[string]s3BucketContext
	logging                    map[string]bool
	versioningEnabled          map[string]bool
	strictPublicAccessBlock    map[string]bool
	serverSideEncryptionConfig map[string]bool
}

func newS3BucketIndex(plan *model.Plan) s3BucketIndex {
	index := s3BucketIndex{
		buckets:                    make(map[string]s3BucketContext),
		logging:                    make(map[string]bool),
		versioningEnabled:          make(map[string]bool),
		strictPublicAccessBlock:    make(map[string]bool),
		serverSideEncryptionConfig: make(map[string]bool),
	}
	if plan == nil {
		return index
	}
	for _, change := range sortedChanges(plan) {
		switch change.Type {
		case "aws_s3_bucket":
			ctx := s3BucketContext{
				Address: change.Address,
				Name:    change.Name,
				Bucket:  asString(change.After["bucket"]),
			}
			ctx.Keys = dedupeStrings([]string{ctx.Address, ctx.Name, ctx.Bucket, asString(change.After["id"])})
			for _, key := range ctx.Keys {
				if key != "" {
					index.buckets[key] = ctx
				}
			}
		}
	}
	for _, change := range sortedChanges(plan) {
		keys := index.bucketKeys(plan, change)
		switch change.Type {
		case "aws_s3_bucket_logging":
			index.mark(index.logging, keys)
		case "aws_s3_bucket_versioning":
			status := strings.ToLower(asString(firstNestedValue(change.After["versioning_configuration"], "status")))
			if status == "enabled" {
				index.mark(index.versioningEnabled, keys)
			}
		case "aws_s3_bucket_public_access_block":
			if truthy(change.After["block_public_acls"]) &&
				truthy(change.After["block_public_policy"]) &&
				truthy(change.After["ignore_public_acls"]) &&
				truthy(change.After["restrict_public_buckets"]) {
				index.mark(index.strictPublicAccessBlock, keys)
			}
		case "aws_s3_bucket_server_side_encryption_configuration":
			index.mark(index.serverSideEncryptionConfig, keys)
		}
	}
	return index
}

func (index s3BucketIndex) bucketKeys(plan *model.Plan, change model.Change) []string {
	keys := []string{
		change.Address,
		change.Name,
		asString(change.After["bucket"]),
		asString(change.After["id"]),
	}
	for _, ref := range configuredResourceReferences(plan, change.Address, "bucket") {
		keys = append(keys, ref)
		if bucket, ok := index.buckets[ref]; ok {
			keys = append(keys, bucket.Keys...)
		}
	}
	return dedupeStrings(keys)
}

func (index s3BucketIndex) mark(target map[string]bool, keys []string) {
	for _, key := range keys {
		if key != "" {
			target[key] = true
		}
	}
}

func hasAnyBucketKey(index map[string]bool, keys []string) bool {
	for _, key := range keys {
		if index[key] {
			return true
		}
	}
	return false
}

func bucketHasVersioningEnabled(bucket model.Change, index s3BucketIndex, plan *model.Plan) bool {
	return hasAnyBucketKey(index.versioningEnabled, index.bucketKeys(plan, bucket))
}

func hasStrictPublicAccessBlock(bucket model.Change, index s3BucketIndex, plan *model.Plan) bool {
	return hasAnyBucketKey(index.strictPublicAccessBlock, index.bucketKeys(plan, bucket))
}

func bucketHasEncryption(bucket model.Change, index s3BucketIndex, plan *model.Plan) bool {
	if !encryptionDisabled(bucket.After) {
		return true
	}
	return hasAnyBucketKey(index.serverSideEncryptionConfig, index.bucketKeys(plan, bucket))
}

func hasEquivalentObjectAudit(change model.Change) bool {
	text := normalizedChangeText(change)
	return strings.Contains(text, "cloudtrail") && strings.Contains(text, "data")
}

func configuredResourceReferences(plan *model.Plan, address string, expressionPath ...string) []string {
	if plan == nil || plan.Configuration == nil {
		return nil
	}
	var rawConfig map[string]any
	for _, resource := range plan.Configuration.Resources {
		if resource.Address == address {
			rawConfig = resource.Expressions
			break
		}
	}
	if len(rawConfig) == 0 {
		return nil
	}
	var current any = rawConfig
	for _, key := range expressionPath {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = obj[key]
	}
	return resourceAddressesFromReferences(referencesInExpression(current))
}

func referencesInExpression(value any) []string {
	out := make([]string, 0)
	switch typed := value.(type) {
	case map[string]any:
		out = append(out, stringList(typed["references"])...)
		for key, nested := range typed {
			if key == "references" {
				continue
			}
			out = append(out, referencesInExpression(nested)...)
		}
	case []any:
		for _, item := range typed {
			out = append(out, referencesInExpression(item)...)
		}
	}
	return dedupeStrings(out)
}

func resourceAddressesFromReferences(references []string) []string {
	out := make([]string, 0, len(references))
	for _, ref := range references {
		parts := strings.Split(ref, ".")
		if len(parts) < 2 {
			continue
		}
		addressParts := parts[:2]
		if parts[0] == "module" && len(parts) >= 4 {
			addressParts = parts[:4]
		}
		out = append(out, strings.Join(addressParts, "."))
	}
	return dedupeStrings(out)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func policyAllowsPublicPrincipal(text string) bool {
	normalized := normalizePolicyText(text)
	return strings.Contains(normalized, `"principal":"*"`) ||
		strings.Contains(normalized, `"aws":"*"`) ||
		strings.Contains(normalized, `"principal":{"aws":"*"}`) ||
		strings.Contains(normalized, `"principal":{"canonicaluser":"*"}`)
}

func policyAllowsActions(text string, actions ...string) bool {
	normalized := normalizePolicyText(text)
	for _, action := range actions {
		action = strings.ToLower(action)
		if action == "*" {
			if strings.Contains(normalized, `"action":"*"`) || strings.Contains(normalized, `"action":["*"`) {
				return true
			}
			continue
		}
		if strings.Contains(normalized, action) {
			return true
		}
	}
	return false
}

func policyHasWildcardResource(text string) bool {
	normalized := normalizePolicyText(text)
	return strings.Contains(normalized, `"resource":"*"`) || strings.Contains(normalized, `"resource":["*"`)
}

func policyHasAllowNotAction(text string) bool {
	normalized := normalizePolicyText(text)
	return strings.Contains(normalized, `"effect":"allow"`) && strings.Contains(normalized, `"notaction"`)
}

func firstNestedValue(value any, key string) any {
	for _, item := range asList(value) {
		if obj, ok := item.(map[string]any); ok {
			if nested, exists := obj[key]; exists {
				return nested
			}
		}
	}
	return nil
}

func statefulOpenSecurityGroupFindings(input RuleInput, meta Metadata, resourceTypes map[string]bool, message string, remediation string) []model.Finding {
	publicSGs := publicSecurityGroups(input)
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if !resourceTypes[change.Type] || !hasProductionOrSensitiveContext(change) {
			continue
		}
		for _, sg := range append(stringList(change.After["security_group_ids"]), stringList(change.After["vpc_security_group_ids"])...) {
			if publicSGs[sg] || strings.Contains(strings.ToLower(sg), "public") {
				out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "security_group_ids", sg, message)}, remediation))
				break
			}
		}
	}
	if input.Graph == nil {
		return out
	}
	seen := make(map[string]bool, len(out))
	for _, existing := range out {
		seen[existing.ResourceAddress] = true
	}
	for id, node := range sortedNodes(input.Graph) {
		if node == nil || !resourceTypes[node.Type] || !hasSensitiveGraphContext(node) || seen[node.Address] {
			continue
		}
		for _, candidate := range sortedNodes(input.Graph) {
			if candidate == nil || candidate.Type != "aws_security_group" {
				continue
			}
			sgID := graph.ResourceID(candidate.ID)
			if !input.Graph.IsInternetExposed(sgID) || !input.Graph.CanReach(sgID, id) {
				continue
			}
			out = append(out, finding(meta, node.Address, node.Provider, node.Environment, exposureEvidence(input.Graph, sgID, id, node.Address), remediation))
			seen[node.Address] = true
			break
		}
	}
	return out
}

func publicSecurityGroups(input RuleInput) map[string]bool {
	out := make(map[string]bool)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_security_group" && change.Type != "aws_vpc_security_group_ingress_rule" {
			continue
		}
		if !publicCIDRInChange(change) {
			continue
		}
		for _, value := range []string{
			change.Address,
			change.Name,
			asString(change.After["id"]),
			asString(change.After["name"]),
			asString(change.After["security_group_id"]),
		} {
			if value != "" {
				out[value] = true
			}
		}
	}
	return out
}

func hasSensitiveGraphContext(node *graph.Node) bool {
	if node == nil {
		return false
	}
	if node.Environment == "production" {
		return true
	}
	text := strings.ToLower(node.Address + " " + node.Name + " " + fmt.Sprint(node.Tags) + " " + asJSON(node.Values))
	for _, marker := range []string{"prod", "production", "sensitive", "customer", "payment", "pii", "backup", "secret"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func isRDS(typ string) bool {
	return typ == "aws_db_instance" || typ == "aws_rds_cluster"
}

func isReplacement(change model.Change) bool {
	if len(change.Actions) == 1 && change.Actions[0] == model.ActionReplace {
		return true
	}
	hasCreate := false
	hasDelete := false
	for _, action := range change.Actions {
		hasCreate = hasCreate || action == model.ActionCreate
		hasDelete = hasDelete || action == model.ActionDelete
	}
	return hasCreate && hasDelete
}

func statefulType(typ string) bool {
	switch typ {
	case "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_efs_file_system", "aws_dynamodb_table", "aws_elasticache_cluster", "aws_elasticache_replication_group":
		return true
	default:
		return false
	}
}

func encryptionDisabled(values map[string]any) bool {
	for _, key := range []string{"storage_encrypted", "encrypted", "server_side_encryption_configuration"} {
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case bool:
				return !typed
			case nil:
				return true
			case []any:
				return len(typed) == 0
			case string:
				return typed == "" || strings.EqualFold(typed, "false")
			}
		}
	}
	return false
}

func isSensitiveBucket(change model.Change) bool {
	text := strings.ToLower(change.Address + " " + change.Name + " " + fmt.Sprint(change.Tags) + " " + asJSON(change.After["tags"]))
	return strings.Contains(text, "prod") || strings.Contains(text, "sensitive") || strings.Contains(text, "logs") || strings.Contains(text, "backup")
}

func isSensitiveNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	switch node.Type {
	case "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_secretsmanager_secret", "aws_dynamodb_table", "aws_efs_file_system", "aws_elasticache_cluster", "aws_elasticache_replication_group", "aws_kms_key":
		return true
	default:
		return false
	}
}

func hasResourceType(g *graph.Graph, typ string) bool {
	if g == nil {
		return false
	}
	for _, node := range g.Nodes {
		if node.Type == typ {
			return true
		}
	}
	return false
}

func hasAnyChangedType(plan *model.Plan, types ...string) bool {
	set := make(map[string]bool, len(types))
	for _, typ := range types {
		set[typ] = true
	}
	for _, change := range sortedChanges(plan) {
		if set[change.Type] {
			return true
		}
	}
	return false
}

func adminRoleIDs(g *graph.Graph) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for id, node := range g.Nodes {
		if node.Type == "aws_iam_role" && strings.Contains(strings.ToLower(node.Address+" "+node.Name), "admin") {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i int, j int) bool { return out[i] < out[j] })
	return out
}

func policyTextFindings(input RuleInput, meta Metadata, types []string, needles []string, path string, message string, remediation string) []model.Finding {
	typeSet := make(map[string]bool, len(types))
	for _, typ := range types {
		typeSet[typ] = true
	}
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if !typeSet[change.Type] {
			continue
		}
		text := normalizePolicyText(asString(change.After[path]))
		if text == "" || text == "null" {
			text = normalizePolicyText(asJSON(change.After))
		}
		ok := true
		for _, needle := range needles {
			if !strings.Contains(text, normalizePolicyText(needle)) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, path, "(policy)", message)}, remediation))
		}
	}
	return out
}

func normalizePolicyText(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "\\", "")
	return value
}
