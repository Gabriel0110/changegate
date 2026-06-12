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
		fmt.Fprintf(&b, "- Decision: `%s`\n", path.Decision)
		fmt.Fprintf(&b, "- Severity: `%s`, confidence: `%s`\n", path.Severity, path.Confidence)
		if path.ConfidenceReason != "" {
			fmt.Fprintf(&b, "- Confidence reason: %s\n", path.ConfidenceReason)
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
				if resource.Role != "" {
					fmt.Fprintf(&b, "- **%s:** `%s`", humanizeToken(resource.Role), resource.Resource)
				} else {
					fmt.Fprintf(&b, "- `%s`", resource.Resource)
				}
				if resource.Type != "" {
					fmt.Fprintf(&b, " (`%s`)", resource.Type)
				}
				b.WriteString("\n")
			}
		}
		if len(path.Steps) > 0 {
			b.WriteString("\nSteps:\n")
			for _, step := range path.Steps {
				fmt.Fprintf(&b, "1. `%s` -> `%s`", step.From, step.To)
				if step.Action != "" {
					fmt.Fprintf(&b, " via %s", humanizeToken(step.Action))
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
	return normalizeMarkdownFinalNewline(b.String())
}

func humanizeToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	switch value {
	case "iam:PassRole", "sts:AssumeRole", "lambda:UpdateFunctionCode", "lambda:CreateFunction", "ecs:UpdateService":
		return value
	}
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	words := strings.Fields(value)
	for index, word := range words {
		if strings.HasPrefix(word, "aws") || strings.Contains(word, ":") {
			continue
		}
		words[index] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

func normalizeMarkdownFinalNewline(value string) string {
	value = strings.TrimRight(value, "\n") + "\n"
	return value
}
