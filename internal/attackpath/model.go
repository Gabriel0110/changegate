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
	ResultVersion = 1
)

// Type classifies the high-signal attack path family.
type Type string

const (
	// TypePublicToSensitiveData is an internet-to-sensitive-asset path.
	TypePublicToSensitiveData Type = "public_to_sensitive_data"
	// TypeIAMPrivilegeEscalation is a principal-to-privileged-access path.
	TypeIAMPrivilegeEscalation Type = "iam_privilege_escalation"
)

// AttackPath is first-class evidence for deploy decisioning and review output.
type AttackPath struct {
	ID          string            `json:"id"`
	Type        Type              `json:"type"`
	Title       string            `json:"title"`
	Severity    model.Severity    `json:"severity"`
	Confidence  model.Confidence  `json:"confidence"`
	Decision    model.Decision    `json:"decision"`
	Principal   string            `json:"principal,omitempty"`
	Entrypoint  string            `json:"entrypoint,omitempty"`
	Target      string            `json:"target,omitempty"`
	Steps       []Step            `json:"steps,omitempty"`
	Evidence    []model.Evidence  `json:"evidence,omitempty"`
	Mitigations []string          `json:"mitigations,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Step describes one directed transition in an attack path.
type Step struct {
	From        string         `json:"from"`
	To          string         `json:"to"`
	Action      string         `json:"action"`
	EdgeType    graph.EdgeType `json:"edge_type,omitempty"`
	Explanation string         `json:"explanation,omitempty"`
}

// Result is the stable JSON envelope for attack path renderers and future CLI output.
type Result struct {
	Version int          `json:"version"`
	Paths   []AttackPath `json:"paths"`
}

// PolicyOptions controls whether an attack path may affect deploy decisions.
type PolicyOptions struct {
	Enabled                   bool
	BlockHighConfidence       bool
	AllowMediumConfidenceWarn bool
}

// Normalize returns sanitized, ID-stable, deterministically sorted attack paths.
func Normalize(paths []AttackPath) []AttackPath {
	out := make([]AttackPath, 0, len(paths))
	for _, path := range paths {
		current := path
		if current.ID == "" {
			current.ID = StableID(current)
		}
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

// CanInfluenceDecision reports whether a path is eligible to affect policy.
func CanInfluenceDecision(path AttackPath, opts PolicyOptions) bool {
	if !opts.Enabled {
		return false
	}
	if path.Confidence == model.ConfidenceHigh {
		return true
	}
	return opts.AllowMediumConfidenceWarn && path.Confidence == model.ConfidenceMedium && path.Decision == model.DecisionWarn
}

// ShouldBlock reports whether a path can produce a blocking policy effect.
func ShouldBlock(path AttackPath, opts PolicyOptions) bool {
	return opts.Enabled &&
		opts.BlockHighConfidence &&
		path.Confidence == model.ConfidenceHigh &&
		path.Decision == model.DecisionBlock
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
