package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	// DiagnosticCloudPublicConflict means live context reports a public resource missing from plan exposure.
	DiagnosticCloudPublicConflict = "CLOUD_CONTEXT_PUBLIC_CONFLICT"
	// DiagnosticCloudAttachmentConflict means live context reports an attachment absent from the plan graph.
	DiagnosticCloudAttachmentConflict = "CLOUD_CONTEXT_ATTACHMENT_CONFLICT"
	// DiagnosticCloudUnmanagedRelationship means a managed resource is attached to an unmanaged live resource.
	DiagnosticCloudUnmanagedRelationship = "CLOUD_CONTEXT_UNMANAGED_RELATIONSHIP"
)

// MergeContext returns a graph that combines planned changes and live cloud context.
//
// The input graph is not mutated. Live context can add nodes, edges, provenance,
// and conflict diagnostics, but an empty or partial snapshot never removes plan
// evidence.
func MergeContext(planGraph *Graph, snapshot cloudcontext.Snapshot) (*Graph, []model.Diagnostic) {
	merged := copyGraph(planGraph)
	cloudcontext.Normalize(&snapshot)
	if merged == nil {
		merged = &Graph{Nodes: make(map[ResourceID]*Node)}
	}
	if merged.Nodes == nil {
		merged.Nodes = make(map[ResourceID]*Node)
	}

	index := newContextIndex(merged)
	resources := contextResources(snapshot)
	resourceIDs := make(map[string]ResourceID, len(resources))
	var diagnostics []model.Diagnostic

	keys := make([]string, 0, len(resources))
	for key := range resources {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		resource := resources[key]
		id, matched := mergeContextResource(merged, index, key, resource)
		resourceIDs[key] = id
		index.addResourceAliases(id, key, resource)
		if matched && resourcePublic(resource) && !merged.hasPublicInboundEdge(id) {
			diagnostics = append(diagnostics, model.Diagnostic{
				Severity: model.DiagnosticWarning,
				Code:     DiagnosticCloudPublicConflict,
				Message:  fmt.Sprintf("cloud context shows %s is public but the plan graph has no public inbound path", id),
			})
		}
		if resourcePublic(resource) {
			merged.ensureSynthetic(InternetNodeID, "internet", "internet")
			merged.addEdgeWithProvenance(InternetNodeID, id, EdgeHasPublicAccess, SourceCloudContext, ConfidenceHigh, contextEvidence(id, "public", true, "cloud context marks resource public"), map[string]string{"cloud_context_key": key})
		}
		if !matched && resource.TerraformAddress != "" && looksTerraformAddress(resource.TerraformAddress) {
			resourceIDs[resource.TerraformAddress] = id
		}
	}

	for _, relationship := range snapshot.Relationships {
		from, fromManaged := resolveContextEndpoint(index, resourceIDs, relationship.From)
		to, toManaged := resolveContextEndpoint(index, resourceIDs, relationship.To)
		if from == "" || to == "" || from == to {
			continue
		}
		edgeType := contextEdgeType(relationship.Type)
		if (fromManaged || toManaged) && !graphHasEdge(merged, from, to, edgeType) && attachmentRelationship(relationship.Type) {
			diagnostics = append(diagnostics, model.Diagnostic{
				Severity: model.DiagnosticWarning,
				Code:     DiagnosticCloudAttachmentConflict,
				Message:  fmt.Sprintf("cloud context shows live relationship %s --%s--> %s that is absent from the plan graph", from, relationship.Type, to),
			})
		}
		if fromManaged != toManaged && attachmentRelationship(relationship.Type) {
			diagnostics = append(diagnostics, model.Diagnostic{
				Severity: model.DiagnosticWarning,
				Code:     DiagnosticCloudUnmanagedRelationship,
				Message:  fmt.Sprintf("cloud context shows Terraform-managed resource attached to unmanaged live resource: %s --%s--> %s", from, relationship.Type, to),
			})
		}
		source := SourceCloudContext
		confidence := contextConfidence(relationship.Confidence)
		metadata := map[string]string{
			"cloud_context_type": relationship.Type,
		}
		if relationship.Source != "" {
			metadata["cloud_context_source"] = relationship.Source
		}
		merged.addEdgeWithProvenance(from, to, edgeType, source, confidence, contextEvidence(from, relationship.Type, to, "cloud context relationship"), metadata)
	}

	merged.sort()
	sortDiagnostics(diagnostics)
	return merged, diagnostics
}

type contextIndex struct {
	aliases map[string]ResourceID
	managed map[ResourceID]bool
}

func newContextIndex(g *Graph) *contextIndex {
	index := &contextIndex{
		aliases: make(map[string]ResourceID),
		managed: make(map[ResourceID]bool),
	}
	if g == nil {
		return index
	}
	for id, node := range g.Nodes {
		index.addAlias(string(id), id)
		if node == nil {
			continue
		}
		index.managed[id] = !node.Synthetic && node.Address != "" && node.Address == string(id)
		index.addAlias(node.Address, id)
		index.addAlias(node.Name, id)
		for _, key := range []string{"arn", "id", "resource_id", "name"} {
			index.addAlias(asStringValue(node.Values, key), id)
		}
		for _, key := range []string{"Name", "name", "terraform_address", "TerraformAddress"} {
			index.addAlias(node.Tags[key], id)
		}
	}
	return index
}

func (i *contextIndex) addResourceAliases(id ResourceID, key string, resource cloudcontext.Resource) {
	i.addAlias(key, id)
	i.addAlias(resource.TerraformAddress, id)
	i.addAlias(resource.ARN, id)
	i.addAlias(resource.ID, id)
	i.addAlias(resource.Attributes["name"], id)
	i.addAlias(resource.Attributes["resource_id"], id)
	i.addAlias(resource.Tags["Name"], id)
	i.addAlias(resource.Tags["name"], id)
	i.addAlias(resource.Tags["terraform_address"], id)
	i.addAlias(resource.Tags["TerraformAddress"], id)
}

func (i *contextIndex) addAlias(alias string, id ResourceID) {
	alias = strings.TrimSpace(alias)
	if alias == "" || id == "" {
		return
	}
	if _, exists := i.aliases[alias]; !exists {
		i.aliases[alias] = id
	}
}

func contextResources(snapshot cloudcontext.Snapshot) map[string]cloudcontext.Resource {
	out := make(map[string]cloudcontext.Resource)
	for _, set := range []cloudcontext.ResourceSet{snapshot.Network, snapshot.IAM, snapshot.Data, snapshot.Compute, snapshot.Edge} {
		for key, resource := range set.Resources {
			if key == "" {
				key = firstNonEmpty(resource.TerraformAddress, resource.ARN, resource.ID)
			}
			if key != "" {
				out[key] = resource
			}
		}
	}
	return out
}

func mergeContextResource(g *Graph, index *contextIndex, key string, resource cloudcontext.Resource) (ResourceID, bool) {
	id, matched := resolveResourceID(index, key, resource)
	if id == "" {
		id = ResourceID(firstNonEmpty(resource.TerraformAddress, resource.ARN, resource.ID, key))
	}
	if id == "" {
		return "", false
	}
	if existing := g.Nodes[id]; existing != nil {
		mergeContextIntoNode(existing, resource)
		index.managed[id] = index.managed[id] || (!existing.Synthetic && existing.Address == string(id))
		return id, matched
	}
	g.Nodes[id] = contextNode(id, key, resource)
	index.managed[id] = false
	return id, false
}

func resolveResourceID(index *contextIndex, key string, resource cloudcontext.Resource) (ResourceID, bool) {
	for _, candidate := range []string{
		resource.TerraformAddress,
		key,
		resource.ARN,
		resource.ID,
		resource.Attributes["name"],
		resource.Attributes["resource_id"],
		resource.Tags["Name"],
		resource.Tags["name"],
		resource.Tags["terraform_address"],
		resource.Tags["TerraformAddress"],
	} {
		if id, ok := index.aliases[candidate]; ok {
			return id, true
		}
	}
	return "", false
}

func resolveContextEndpoint(index *contextIndex, ids map[string]ResourceID, endpoint string) (ResourceID, bool) {
	if id := ids[endpoint]; id != "" {
		return id, index.managed[id]
	}
	if id := index.aliases[endpoint]; id != "" {
		return id, index.managed[id]
	}
	id := ResourceID(strings.TrimSpace(endpoint))
	return id, false
}

func contextNode(id ResourceID, key string, resource cloudcontext.Resource) *Node {
	values := contextValues(key, resource)
	return &Node{
		ID:          id,
		Address:     firstNonEmpty(resource.TerraformAddress, string(id)),
		Type:        firstNonEmpty(resource.Type, "external"),
		Kind:        contextNodeKind(resource, values),
		Name:        contextNodeName(id, key, resource),
		Provider:    "aws",
		Environment: environmentFromTags(resource.Tags),
		Tags:        copyTags(resource.Tags),
		Values:      values,
		Synthetic:   true,
	}
}

func mergeContextIntoNode(node *Node, resource cloudcontext.Resource) {
	if node.Tags == nil {
		node.Tags = make(map[string]string)
	}
	mergeTags(node.Tags, resource.Tags)
	if node.Values == nil {
		node.Values = make(map[string]any)
	}
	for key, value := range contextValues("", resource) {
		if _, exists := node.Values[key]; !exists {
			node.Values[key] = value
		}
	}
	if node.Environment == "" {
		node.Environment = environmentFromTags(node.Tags)
	}
	if node.Kind == NodeUnknown || resource.SensitiveData || resource.Sensitivity.Data || resourcePublic(resource) {
		node.Kind = contextNodeKind(resource, node.Values)
	}
}

func contextValues(key string, resource cloudcontext.Resource) map[string]any {
	values := make(map[string]any)
	addStringValue(values, "cloud_context_key", key)
	addStringValue(values, "terraform_address", resource.TerraformAddress)
	addStringValue(values, "arn", resource.ARN)
	addStringValue(values, "id", resource.ID)
	addStringValue(values, "account_id", resource.AccountID)
	addStringValue(values, "region", resource.Region)
	for attrKey, attrValue := range resource.Attributes {
		addStringValue(values, attrKey, attrValue)
	}
	if resource.Public != nil {
		values["public"] = *resource.Public
	}
	if resource.EncryptionEnabled != nil {
		values["encryption_enabled"] = *resource.EncryptionEnabled
	}
	if resource.PublicAccessBlocked != nil {
		values["public_access_blocked"] = *resource.PublicAccessBlocked
	}
	if resource.DeletionProtection != nil {
		values["deletion_protection"] = *resource.DeletionProtection
	}
	if resource.EndpointPublicAccess != nil {
		values["endpoint_public_access"] = *resource.EndpointPublicAccess
	}
	if resource.SensitiveData || resource.Sensitivity.Data {
		values["sensitive_data"] = true
	}
	if resource.Sensitivity.Reason != "" {
		values["sensitivity_reason"] = resource.Sensitivity.Reason
	}
	if len(resource.CompensatingControls) > 0 {
		values["compensating_controls"] = append([]string(nil), resource.CompensatingControls...)
	}
	if len(resource.RelatedSensitiveData) > 0 {
		values["related_sensitive_data"] = append([]string(nil), resource.RelatedSensitiveData...)
	}
	if len(resource.ObservedPolicyActions) > 0 {
		values["observed_policy_actions"] = append([]string(nil), resource.ObservedPolicyActions...)
	}
	return values
}

func addStringValue(values map[string]any, key string, value string) {
	if value != "" {
		values[key] = value
	}
}

func contextNodeKind(resource cloudcontext.Resource, values map[string]any) NodeKind {
	if resource.SensitiveData || resource.Sensitivity.Data {
		switch resource.Type {
		case "aws_secretsmanager_secret", "aws_ssm_parameter":
			return NodeSecret
		case "aws_kms_key", "aws_kms_alias":
			return NodeKMSKey
		default:
			return NodeDataStore
		}
	}
	if resourcePublic(resource) {
		return NodePublicEntrypoint
	}
	return classifyNodeKind(resource.Type, values)
}

func contextNodeName(id ResourceID, key string, resource cloudcontext.Resource) string {
	return firstNonEmpty(resource.Tags["Name"], resource.Tags["name"], resource.Attributes["name"], resource.ID, key, string(id))
}

func contextEdgeType(relationshipType string) EdgeType {
	switch strings.ToLower(strings.TrimSpace(relationshipType)) {
	case "routes_to", "has_listener", "target_health":
		return EdgeRoutesTo
	case "attached_to", "associated_with", "uses_instance_profile", "inline_policy", "attached_policy":
		return EdgeAttachedTo
	case "contains", "contains_role":
		return EdgeContainedIn
	case "allows_security_group", "allows_ingress":
		return EdgeAllowsIngress
	case "allows_egress":
		return EdgeAllowsEgress
	case "protects":
		return EdgeProtects
	case "uses_role", "assume_role", "trusts", "assumes_role":
		return EdgeCanAssume
	case "passes_role", "pass_role":
		return EdgeCanPassRole
	case "reads_secret":
		return EdgeReadsSecret
	case "uses_kms_key":
		return EdgeEncryptsWith
	case "grants_action", "grants_resource", "grants_permission":
		return EdgeGrantsPermission
	case "network_reaches":
		return EdgeRoutesTo
	default:
		return EdgeDependsOn
	}
}

func contextConfidence(value string) EdgeConfidence {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(ConfidenceLow):
		return ConfidenceLow
	case string(ConfidenceMedium):
		return ConfidenceMedium
	default:
		return ConfidenceHigh
	}
}

func attachmentRelationship(relationshipType string) bool {
	switch strings.ToLower(strings.TrimSpace(relationshipType)) {
	case "attached_to", "associated_with", "uses_instance_profile", "protects", "allows_security_group", "contains", "contains_role":
		return true
	default:
		return false
	}
}

func resourcePublic(resource cloudcontext.Resource) bool {
	return resource.Public != nil && *resource.Public || resource.EndpointPublicAccess != nil && *resource.EndpointPublicAccess
}

func graphHasEdge(g *Graph, from ResourceID, to ResourceID, edgeType EdgeType) bool {
	if g == nil {
		return false
	}
	target := Edge{From: from, To: to, Type: edgeType}
	for _, edge := range g.Edges {
		if edgeKey(edge) == edgeKey(target) {
			return true
		}
	}
	return false
}

func contextEvidence(resource ResourceID, path string, value any, message string) []model.Evidence {
	return []model.Evidence{{
		Type:     "cloud_context",
		Resource: string(resource),
		Path:     path,
		Value:    value,
		Message:  message,
	}}
}

func copyGraph(g *Graph) *Graph {
	if g == nil {
		return &Graph{Nodes: make(map[ResourceID]*Node)}
	}
	out := &Graph{
		Nodes: make(map[ResourceID]*Node, len(g.Nodes)),
		Edges: make([]Edge, len(g.Edges)),
	}
	for id, node := range g.Nodes {
		out.Nodes[id] = copyNode(node)
	}
	for index, edge := range g.Edges {
		out.Edges[index] = copyEdge(edge)
	}
	return out
}

func copyEdge(edge Edge) Edge {
	out := edge
	out.Evidence = append([]model.Evidence(nil), edge.Evidence...)
	out.Metadata = copyEdgeMetadata(edge.Metadata)
	return out
}

func asStringValue(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, ok := values[key]
	if !ok {
		return ""
	}
	return asString(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func looksTerraformAddress(value string) bool {
	return strings.Contains(value, ".") && !strings.Contains(value, "arn:")
}

func sortDiagnostics(diagnostics []model.Diagnostic) {
	sort.SliceStable(diagnostics, func(i int, j int) bool {
		left := diagnostics[i]
		right := diagnostics[j]
		return left.Code+"\x00"+left.Message < right.Code+"\x00"+right.Message
	})
}
