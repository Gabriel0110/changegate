package visual

import (
	"fmt"
	"sort"
	"strings"
)

// RenderMermaid renders a diagram as a Mermaid flowchart.
func RenderMermaid(diagram Diagram) []byte {
	var b strings.Builder
	ids := mermaidIDs(diagram.Nodes)
	b.WriteString("flowchart LR\n")
	if diagram.Title != "" {
		fmt.Fprintf(&b, "  %%%% %s\n", sanitizeMermaidComment(diagram.Title))
	}
	for _, node := range diagram.Nodes {
		label := node.Label
		if label == "" {
			label = node.ID
		}
		label = escapeMermaidLabel(label)
		if node.Kind != "" {
			label += "<br/>" + escapeMermaidLabel(node.Kind)
		}
		fmt.Fprintf(&b, "  %s[\"%s\"]\n", ids[node.ID], label)
	}
	for _, edge := range diagram.Edges {
		from := ids[edge.From]
		to := ids[edge.To]
		if from == "" || to == "" {
			continue
		}
		if edge.Label == "" {
			fmt.Fprintf(&b, "  %s --> %s\n", from, to)
		} else {
			fmt.Fprintf(&b, "  %s -->|\"%s\"| %s\n", from, escapeMermaidLabel(edge.Label), to)
		}
	}
	writeMermaidClasses(&b)
	for _, node := range diagram.Nodes {
		fmt.Fprintf(&b, "  class %s %s\n", ids[node.ID], mermaidClass(node.Role))
	}
	return []byte(b.String())
}

func mermaidIDs(nodes []Node) map[string]string {
	sorted := append([]Node{}, nodes...)
	sort.SliceStable(sorted, func(i int, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	ids := make(map[string]string, len(sorted))
	for index, node := range sorted {
		ids[node.ID] = fmt.Sprintf("n%d", index+1)
	}
	return ids
}

func writeMermaidClasses(b *strings.Builder) {
	b.WriteString("  classDef default fill:#f8fafc,stroke:#94a3b8,color:#0f172a\n")
	b.WriteString("  classDef changed fill:#fff7ed,stroke:#f97316,color:#7c2d12\n")
	b.WriteString("  classDef public fill:#eff6ff,stroke:#2563eb,color:#1e3a8a\n")
	b.WriteString("  classDef workload fill:#ecfeff,stroke:#0891b2,color:#164e63\n")
	b.WriteString("  classDef sensitive fill:#fef2f2,stroke:#dc2626,color:#7f1d1d\n")
	b.WriteString("  classDef principal fill:#f5f3ff,stroke:#7c3aed,color:#3b0764\n")
	b.WriteString("  classDef policy fill:#fdf4ff,stroke:#c026d3,color:#701a75\n")
	b.WriteString("  classDef network fill:#f0fdf4,stroke:#16a34a,color:#14532d\n")
	b.WriteString("  classDef path fill:#eef2ff,stroke:#4f46e5,color:#312e81\n")
	b.WriteString("  classDef block fill:#fee2e2,stroke:#b91c1c,color:#7f1d1d\n")
	b.WriteString("  classDef warn fill:#fef3c7,stroke:#d97706,color:#78350f\n")
	b.WriteString("  classDef allow fill:#dcfce7,stroke:#16a34a,color:#14532d\n")
	b.WriteString("  classDef internet fill:#e0f2fe,stroke:#0284c7,color:#0c4a6e\n")
}

func mermaidClass(role Role) string {
	switch role {
	case RoleChanged, RolePublic, RoleWorkload, RoleSensitive, RolePrincipal, RolePolicy, RoleNetwork, RolePath, RoleBlock, RoleWarn, RoleAllow, RoleInternet:
		return string(role)
	default:
		return "default"
	}
}

func escapeMermaidLabel(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "\"", "&quot;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	return value
}

func sanitizeMermaidComment(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}
