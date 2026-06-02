package attackpath

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderJSON renders a deterministic attack path result document.
func RenderJSON(paths []AttackPath) ([]byte, error) {
	result := Result{
		Version: ResultVersion,
		Paths:   Normalize(paths),
	}
	return json.MarshalIndent(result, "", "  ")
}

// RenderMarkdown renders concise review-ready attack path output.
func RenderMarkdown(paths []AttackPath) string {
	paths = Normalize(paths)
	var b strings.Builder
	b.WriteString("# Attack Paths\n\n")
	if len(paths) == 0 {
		b.WriteString("No attack paths detected.\n")
		return b.String()
	}
	for index, path := range paths {
		fmt.Fprintf(&b, "## %s\n\n", path.Title)
		fmt.Fprintf(&b, "- ID: `%s`\n", path.ID)
		fmt.Fprintf(&b, "- Type: `%s`\n", path.Type)
		if path.Kind != "" {
			fmt.Fprintf(&b, "- Kind: `%s`\n", path.Kind)
		}
		fmt.Fprintf(&b, "- Decision: `%s`\n", path.Decision)
		fmt.Fprintf(&b, "- Severity: `%s`\n", path.Severity)
		fmt.Fprintf(&b, "- Confidence: `%s`\n", path.Confidence)
		if path.ConfidenceReason != "" {
			fmt.Fprintf(&b, "- Confidence reason: %s\n", path.ConfidenceReason)
		}
		if path.Source != "" {
			fmt.Fprintf(&b, "- Source: `%s`\n", path.Source)
		}
		if len(path.FindingRuleIDs) > 0 {
			fmt.Fprintf(&b, "- Finding rules: `%s`\n", strings.Join(path.FindingRuleIDs, "`, `"))
		}
		if path.Principal != "" {
			fmt.Fprintf(&b, "- Principal: `%s`\n", path.Principal)
		}
		if path.Entrypoint != "" {
			fmt.Fprintf(&b, "- Entrypoint: `%s`\n", path.Entrypoint)
		}
		if path.Target != "" {
			fmt.Fprintf(&b, "- Target: `%s`\n", path.Target)
		}
		if len(path.AffectedResources) > 0 {
			b.WriteString("\nAffected resources:\n")
			for _, resource := range path.AffectedResources {
				fmt.Fprintf(&b, "- `%s`", resource.Resource)
				if resource.Role != "" {
					fmt.Fprintf(&b, " `%s`", resource.Role)
				}
				if resource.Type != "" {
					fmt.Fprintf(&b, " `%s`", resource.Type)
				}
				b.WriteString("\n")
			}
		}
		if len(path.Steps) > 0 {
			b.WriteString("\nSteps:\n")
			for _, step := range path.Steps {
				fmt.Fprintf(&b, "1. `%s` -> `%s`", step.From, step.To)
				if step.Action != "" {
					fmt.Fprintf(&b, " via `%s`", step.Action)
				}
				if step.Source != "" || step.Confidence != "" {
					fmt.Fprintf(&b, " (`%s/%s`)", nonEmpty(string(step.Source), "unknown"), nonEmpty(string(step.Confidence), "unknown"))
				}
				if step.Explanation != "" {
					fmt.Fprintf(&b, ": %s", step.Explanation)
				}
				b.WriteString("\n")
			}
		}
		if len(path.Mitigations) > 0 {
			b.WriteString("\nMitigations:\n")
			for _, mitigation := range path.Mitigations {
				fmt.Fprintf(&b, "- %s\n", mitigation)
			}
		}
		if len(path.References) > 0 {
			b.WriteString("\nReferences:\n")
			for _, reference := range path.References {
				fmt.Fprintf(&b, "- %s\n", reference)
			}
		}
		if index < len(paths)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func nonEmpty(value string, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
