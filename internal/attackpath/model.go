// Package attackpath defines deterministic attack path evidence models.
package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	// ResultVersion is the current attack path JSON result contract.
	ResultVersion = 2
)

// Type classifies the high-signal attack path family.
type Type string

const (
	// TypePublicToSensitiveData is an internet-to-sensitive-asset path.
	TypePublicToSensitiveData Type = "public_to_sensitive_data"
	// TypeIAMPrivilegeEscalation is a principal-to-privileged-access path.
	TypeIAMPrivilegeEscalation Type = "iam_privilege_escalation"
)

// PathKind classifies the main security domain represented by a path.
type PathKind string

const (
	// PathKindNetwork is a public or private reachability path.
	PathKindNetwork PathKind = "network"
	// PathKindIdentity is an IAM or workload identity path.
	PathKindIdentity PathKind = "identity"
)

// AffectedResource identifies a resource that participates in an attack path.
type AffectedResource struct {
	Resource string `json:"resource"`
	Role     string `json:"role"`
	Type     string `json:"type,omitempty"`
}

// AttackPath is first-class evidence for deploy decisioning and review output.
type AttackPath struct {
	ID                string             `json:"id"`
	Type              Type               `json:"type"`
	Kind              PathKind           `json:"kind,omitempty"`
	Title             string             `json:"title"`
	Severity          model.Severity     `json:"severity"`
	Confidence        model.Confidence   `json:"confidence"`
	ConfidenceReason  string             `json:"confidence_reason,omitempty"`
	Decision          model.Decision     `json:"decision"`
	Source            graph.EdgeSource   `json:"source,omitempty"`
	Principal         string             `json:"principal,omitempty"`
	Entrypoint        string             `json:"entrypoint,omitempty"`
	Target            string             `json:"target,omitempty"`
	AffectedResources []AffectedResource `json:"affected_resources,omitempty"`
	FindingRuleIDs    []string           `json:"finding_rule_ids,omitempty"`
	Steps             []Step             `json:"steps,omitempty"`
	Evidence          []model.Evidence   `json:"evidence,omitempty"`
	Mitigations       []string           `json:"mitigations,omitempty"`
	References        []string           `json:"references,omitempty"`
	Metadata          map[string]string  `json:"metadata,omitempty"`
}

// Step describes one directed transition in an attack path.
type Step struct {
	From        string               `json:"from"`
	To          string               `json:"to"`
	Action      string               `json:"action"`
	EdgeType    graph.EdgeType       `json:"edge_type,omitempty"`
	Source      graph.EdgeSource     `json:"source,omitempty"`
	Confidence  graph.EdgeConfidence `json:"confidence,omitempty"`
	Explanation string               `json:"explanation,omitempty"`
	Evidence    []model.Evidence     `json:"evidence,omitempty"`
	Metadata    map[string]string    `json:"metadata,omitempty"`
}

// Result is the stable JSON envelope for attack path renderers and future CLI output.
type Result struct {
	Version int          `json:"version"`
	Paths   []AttackPath `json:"paths"`
}

// Normalize returns sanitized, ID-stable, deterministically sorted attack paths.
func Normalize(paths []AttackPath) []AttackPath {
	out := make([]AttackPath, 0, len(paths))
	for _, path := range paths {
		current := path
		if current.Kind == "" {
			current.Kind = defaultKind(current.Type)
		}
		if current.Source == "" {
			current.Source = sourceFromSteps(current.Steps)
		}
		if current.ConfidenceReason == "" {
			current.ConfidenceReason = defaultConfidenceReason(current.Confidence, current.Source)
		}
		if len(current.AffectedResources) == 0 {
			current.AffectedResources = affectedResources(current)
		} else {
			current.AffectedResources = normalizeAffectedResources(current.AffectedResources)
		}
		if len(current.FindingRuleIDs) == 0 {
			current.FindingRuleIDs = defaultFindingRuleIDs(current)
		} else {
			current.FindingRuleIDs = dedupeSorted(current.FindingRuleIDs)
		}
		if current.ID == "" {
			current.ID = StableID(current)
		}
		current.Steps = normalizeSteps(current.Steps)
		current.Evidence = model.RedactEvidence(current.Evidence)
		current.Mitigations = dedupeSorted(current.Mitigations)
		current.References = dedupeSorted(current.References)
		current.Metadata = copyMetadata(current.Metadata)
		out = append(out, current)
	}
	Sort(out)
	return out
}

// Sort applies deterministic attack path ordering for reports and comments.
func Sort(paths []AttackPath) {
	sort.SliceStable(paths, func(i int, j int) bool {
		left := paths[i]
		right := paths[j]
		for _, cmp := range []int{
			compareInt(severityRank(right.Severity), severityRank(left.Severity)),
			compareInt(confidenceRank(right.Confidence), confidenceRank(left.Confidence)),
			compareInt(decisionRank(right.Decision), decisionRank(left.Decision)),
			strings.Compare(string(left.Type), string(right.Type)),
			strings.Compare(left.Principal, right.Principal),
			strings.Compare(left.Entrypoint, right.Entrypoint),
			strings.Compare(left.Target, right.Target),
			strings.Compare(left.ID, right.ID),
		} {
			if cmp != 0 {
				return cmp < 0
			}
		}
		return false
	})
}

// StableID returns a deterministic ID derived from non-sensitive path identity.
func StableID(path AttackPath) string {
	hash := sha256.New()
	writeHash(hash, string(path.Type))
	writeHash(hash, string(defaultValue(path.Kind, defaultKind(path.Type))))
	writeHash(hash, path.Principal)
	writeHash(hash, path.Entrypoint)
	writeHash(hash, path.Target)
	for _, step := range path.Steps {
		writeHash(hash, step.From)
		writeHash(hash, step.To)
		writeHash(hash, step.Action)
		writeHash(hash, string(step.EdgeType))
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	return "attack-path-" + sum[:16]
}

func normalizeSteps(steps []Step) []Step {
	if len(steps) == 0 {
		return nil
	}
	out := make([]Step, 0, len(steps))
	for _, step := range steps {
		current := step
		current.Evidence = model.RedactEvidence(current.Evidence)
		current.Metadata = copyMetadata(current.Metadata)
		out = append(out, current)
	}
	return out
}

func defaultKind(pathType Type) PathKind {
	switch pathType {
	case TypeIAMPrivilegeEscalation:
		return PathKindIdentity
	default:
		return PathKindNetwork
	}
}

func defaultValue(value PathKind, fallback PathKind) PathKind {
	if value != "" {
		return value
	}
	return fallback
}

func sourceFromSteps(steps []Step) graph.EdgeSource {
	if len(steps) == 0 {
		return ""
	}
	seen := make(map[graph.EdgeSource]bool)
	for _, step := range steps {
		if step.Source != "" {
			seen[step.Source] = true
		}
	}
	switch len(seen) {
	case 0:
		return ""
	case 1:
		for source := range seen {
			return source
		}
	}
	return graph.EdgeSource("mixed")
}

func defaultConfidenceReason(confidence model.Confidence, source graph.EdgeSource) string {
	if confidence == "" {
		return ""
	}
	if source == "" {
		return "path confidence is based on available graph evidence"
	}
	return "path confidence is based on " + string(source) + " graph evidence"
}

func affectedResources(path AttackPath) []AffectedResource {
	roles := make(map[string]string)
	if path.Principal != "" {
		roles[path.Principal] = "principal"
	}
	if path.Entrypoint != "" {
		roles[path.Entrypoint] = "entrypoint"
	}
	if path.Target != "" {
		if path.Type == TypePublicToSensitiveData {
			roles[path.Target] = "sensitive_asset"
		} else {
			roles[path.Target] = "target"
		}
	}
	for _, step := range path.Steps {
		if step.From != "" && roles[step.From] == "" {
			roles[step.From] = "intermediate"
		}
		if step.To != "" && roles[step.To] == "" {
			roles[step.To] = "intermediate"
		}
	}
	out := make([]AffectedResource, 0, len(roles))
	for resource, role := range roles {
		out = append(out, AffectedResource{Resource: resource, Role: role, Type: resourceType(resource)})
	}
	return normalizeAffectedResources(out)
}

func normalizeAffectedResources(resources []AffectedResource) []AffectedResource {
	byResource := make(map[string]AffectedResource, len(resources))
	for _, resource := range resources {
		resource.Resource = strings.TrimSpace(resource.Resource)
		resource.Role = strings.TrimSpace(resource.Role)
		resource.Type = strings.TrimSpace(resource.Type)
		if resource.Resource == "" {
			continue
		}
		if resource.Role == "" {
			resource.Role = "related"
		}
		if resource.Type == "" {
			resource.Type = resourceType(resource.Resource)
		}
		if existing, ok := byResource[resource.Resource]; ok && roleRank(existing.Role) <= roleRank(resource.Role) {
			continue
		}
		byResource[resource.Resource] = resource
	}
	out := make([]AffectedResource, 0, len(byResource))
	for _, resource := range byResource {
		out = append(out, resource)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].Resource < out[j].Resource
	})
	return out
}

func roleRank(role string) int {
	switch role {
	case "principal", "entrypoint", "target", "sensitive_asset":
		return 1
	case "intermediate":
		return 2
	default:
		return 3
	}
}

func resourceType(resource string) string {
	if resource == "" || resource == string(graph.InternetNodeID) {
		return ""
	}
	if index := strings.LastIndex(resource, "."); index > 0 {
		return resource[:index]
	}
	return ""
}

func defaultFindingRuleIDs(path AttackPath) []string {
	switch path.Type {
	case TypePublicToSensitiveData:
		if path.Decision == model.DecisionWarn && !strings.Contains(strings.ToLower(path.Target), "db") && !strings.Contains(strings.ToLower(path.Target), "secret") {
			return []string{RulePublicAdminServicePath}
		}
		return []string{RulePublicToSensitiveDataPath}
	case TypeIAMPrivilegeEscalation:
		for _, step := range path.Steps {
			if strings.EqualFold(step.Action, "sts:AssumeRole") {
				return []string{RuleIAMAssumeAdminPath}
			}
		}
		return []string{RuleIAMPassRoleFunctionEscalation}
	default:
		return nil
	}
}

func writeHash(hash interface{ Write([]byte) (int, error) }, value string) {
	_, _ = hash.Write([]byte(value))
	_, _ = hash.Write([]byte{0})
}

func copyMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		out[key] = value
	}
	return out
}

func dedupeSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(confidence model.Confidence) int {
	switch confidence {
	case model.ConfidenceHigh:
		return 4
	case model.ConfidenceMedium:
		return 3
	case model.ConfidenceLow:
		return 2
	case model.ConfidenceUnknown:
		return 1
	default:
		return 0
	}
}

func decisionRank(decision model.Decision) int {
	switch decision {
	case model.DecisionError:
		return 4
	case model.DecisionBlock:
		return 3
	case model.DecisionWarn:
		return 2
	case model.DecisionAllow:
		return 1
	default:
		return 0
	}
}

func compareInt(left int, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
