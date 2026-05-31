package visual

import (
	"fmt"
	"sort"
	"strings"
)

// RenderDOT renders a diagram as Graphviz DOT.
func RenderDOT(diagram Diagram) []byte {
	var b strings.Builder
	ids := dotIDs(diagram.Nodes)
	b.WriteString("digraph ChangeGate {\n")
	b.WriteString("  graph [rankdir=LR, bgcolor=\"#ffffff\", pad=\"0.35\", nodesep=\"0.65\", ranksep=\"0.9\", splines=ortho, fontname=\"Inter\"];\n")
	b.WriteString("  node [shape=box, style=\"rounded,filled\", fontname=\"Inter\", fontsize=11, margin=\"0.12,0.08\"];\n")
	b.WriteString("  edge [fontname=\"Inter\", fontsize=9, color=\"#64748b\", arrowsize=0.8];\n")
	if diagram.Title != "" {
		fmt.Fprintf(&b, "  label=%s;\n  labelloc=t;\n  fontsize=18;\n", dotQuote(diagram.Title))
	}
	for _, node := range diagram.Nodes {
		style := styleForRole(node.Role)
		label := node.Label
		if label == "" {
			label = node.ID
		}
		if node.Kind != "" {
			label += "\n" + node.Kind
		}
		fmt.Fprintf(&b, "  %s [label=%s, tooltip=%s, fillcolor=%s, color=%s, fontcolor=%s];\n",
			ids[node.ID],
			dotQuote(label),
			dotQuote(strings.Join(append([]string{node.ID}, node.Details...), "\n")),
			dotQuote(style.Fill),
			dotQuote(style.Stroke),
			dotQuote(style.Text),
		)
	}
	for _, edge := range diagram.Edges {
		from := ids[edge.From]
		to := ids[edge.To]
		if from == "" || to == "" {
			continue
		}
		style := edgeStyleForRole(edge.Role)
		fmt.Fprintf(&b, "  %s -> %s [label=%s, color=%s, penwidth=%s, fontcolor=%s];\n",
			from,
			to,
			dotQuote(edge.Label),
			dotQuote(style.Color),
			style.Width,
			dotQuote(style.Text),
		)
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func dotIDs(nodes []Node) map[string]string {
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

func dotQuote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return "\"" + value + "\""
}
