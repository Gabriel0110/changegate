package visual

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"sort"
	"strings"
)

type positionedNode struct {
	Node
	X float64
	Y float64
}

const (
	htmlNodeWidth       = 230.0
	htmlNodeHeight      = 72.0
	htmlNodeGapX        = 150.0
	htmlNodeGapY        = 150.0
	htmlCanvasPaddingX  = 80.0
	htmlCanvasPaddingY  = 86.0
	htmlFocusColumns    = 3
	htmlEdgeLabelOffset = 18.0
)

// RenderHTML renders a self-contained interactive HTML visualization.
func RenderHTML(diagram Diagram) []byte {
	layout := layoutDiagram(diagram)
	width, height := canvasSize(layout)
	data, _ := json.Marshal(diagramData(diagram))
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<link rel=\"icon\" href=\"data:,\">\n")
	fmt.Fprintf(&b, "<title>%s</title>\n", html.EscapeString(pageTitle(diagram)))
	b.WriteString(`<style>
:root {
  color-scheme: light;
  --bg: #f8fafc;
  --panel: #ffffff;
  --ink: #0f172a;
  --muted: #64748b;
  --line: #cbd5e1;
  --accent: #2563eb;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
header {
  padding: 22px 28px 16px;
  background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
  border-bottom: 1px solid var(--line);
}
h1 { margin: 0; font-size: 24px; line-height: 1.15; letter-spacing: 0; }
.subtitle { margin-top: 6px; color: var(--muted); max-width: 880px; }
.shell {
  display: grid;
  grid-template-columns: minmax(260px, 320px) minmax(0, 1fr);
  grid-template-rows: minmax(560px, 1fr) auto;
  grid-template-areas:
    "controls canvas"
    "controls details";
  min-height: calc(100vh - 84px);
}
aside, .details {
  background: var(--panel);
  border-right: 1px solid var(--line);
  padding: 18px;
  overflow: auto;
}
aside { grid-area: controls; }
.details {
  grid-area: details;
  border-right: 0;
  border-top: 1px solid var(--line);
  max-height: 320px;
}
.canvas-wrap {
  grid-area: canvas;
  position: relative;
  overflow: auto;
  background:
    linear-gradient(#e2e8f0 1px, transparent 1px),
    linear-gradient(90deg, #e2e8f0 1px, transparent 1px);
  background-size: 32px 32px;
}
.toolbar { display: grid; gap: 12px; }
.search {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  font: inherit;
}
.legend { display: grid; gap: 7px; margin-top: 8px; }
.check { display: flex; align-items: center; gap: 8px; color: #334155; }
.swatch { width: 14px; height: 14px; border-radius: 4px; border: 1px solid #94a3b8; flex: none; }
.metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 14px; }
.metric { border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #f8fafc; }
.metric strong { display: block; font-size: 20px; line-height: 1.1; }
.metric span { color: var(--muted); font-size: 12px; }
svg { min-width: 100%; display: block; }
.edge { fill: none; stroke: #64748b; stroke-width: 1.8; marker-end: url(#arrow-default); opacity: .9; }
.edge.path { stroke: #4f46e5; stroke-width: 3; marker-end: url(#arrow-path); }
.edge.block { stroke: #b91c1c; stroke-width: 3; marker-end: url(#arrow-block); }
.edge.warn { stroke: #d97706; stroke-width: 2.6; marker-end: url(#arrow-warn); }
.edge-label {
  fill: #475569;
  font-size: 11px;
  font-weight: 650;
  paint-order: stroke;
  stroke: #fff;
  stroke-width: 7px;
  text-anchor: middle;
}
.node { cursor: pointer; transition: opacity .15s ease, transform .15s ease; }
.node rect { stroke-width: 2; filter: drop-shadow(0 10px 15px rgba(15, 23, 42, .08)); }
.node text { pointer-events: none; }
.node-title { font-weight: 700; fill: #0f172a; font-size: 12px; }
.node-kind { fill: #64748b; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; }
.node.selected rect { stroke: #111827; stroke-width: 3; }
.hidden { opacity: .08; pointer-events: none; }
.details h2 { margin: 0 0 8px; font-size: 18px; }
.details .muted { color: var(--muted); }
.details dl { display: grid; grid-template-columns: 90px 1fr; gap: 6px 12px; margin: 16px 0; }
.details dt { color: var(--muted); }
.details dd { margin: 0; word-break: break-word; }
.details ul { padding-left: 18px; margin: 8px 0; }
@media (max-width: 980px) {
  .shell {
    grid-template-columns: 1fr;
    grid-template-rows: auto minmax(560px, 1fr) auto;
    grid-template-areas:
      "controls"
      "canvas"
      "details";
  }
  aside, .details { border: 0; border-bottom: 1px solid var(--line); }
  .canvas-wrap { min-height: 560px; }
}
</style>
</head>
<body>
`)
	fmt.Fprintf(&b, "<header><h1>%s</h1><div class=\"subtitle\">%s</div></header>\n", html.EscapeString(pageTitle(diagram)), html.EscapeString(diagram.Description))
	b.WriteString("<main class=\"shell\">\n")
	writeHTMLControls(&b, diagram)
	fmt.Fprintf(&b, "<section class=\"canvas-wrap\"><svg id=\"graph\" viewBox=\"0 0 %.0f %.0f\" width=\"%.0f\" height=\"%.0f\" role=\"img\" aria-label=\"%s\">\n", width, height, width, height, html.EscapeString(pageTitle(diagram)))
	writeSVGDefs(&b)
	writeSVGRoutes(&b, layout, diagram.Edges)
	writeSVGNodes(&b, layout)
	b.WriteString("</svg></section>\n")
	b.WriteString("<section class=\"details\" id=\"details\"><h2>Select a node</h2><p class=\"muted\">Click a graph node to inspect its resource identity, role, and evidence details.</p></section>\n")
	b.WriteString("</main>\n")
	fmt.Fprintf(&b, "<script>const CHANGEGATE_DIAGRAM=%s;\n", data)
	b.WriteString(htmlScript())
	b.WriteString("</script>\n</body>\n</html>\n")
	return []byte(b.String())
}

func pageTitle(diagram Diagram) string {
	if diagram.Title == "" {
		return "ChangeGate Visualization"
	}
	return diagram.Title
}

func writeHTMLControls(b *strings.Builder, diagram Diagram) {
	roles := roleCounts(diagram.Nodes)
	b.WriteString("<aside><div class=\"toolbar\">\n")
	b.WriteString("<input id=\"search\" class=\"search\" type=\"search\" placeholder=\"Filter resources\" autocomplete=\"off\">\n")
	b.WriteString("<div class=\"legend\" id=\"legend\">\n")
	for _, role := range sortedRoles(roles) {
		style := styleForRole(role)
		fmt.Fprintf(b, "<label class=\"check\"><input type=\"checkbox\" data-role=\"%s\" checked><span class=\"swatch\" style=\"background:%s;border-color:%s\"></span>%s (%d)</label>\n",
			html.EscapeString(string(role)), style.Fill, style.Stroke, html.EscapeString(roleLabel(role)), roles[role])
	}
	b.WriteString("</div>\n")
	fmt.Fprintf(b, "<div class=\"metrics\"><div class=\"metric\"><strong>%d</strong><span>nodes</span></div><div class=\"metric\"><strong>%d</strong><span>edges</span></div></div>\n", len(diagram.Nodes), len(diagram.Edges))
	if len(diagram.FocusPaths) > 0 {
		fmt.Fprintf(b, "<div class=\"metric\"><strong>%d</strong><span>highlighted paths</span></div>\n", len(diagram.FocusPaths))
	}
	b.WriteString("</div></aside>\n")
}

func writeSVGDefs(b *strings.Builder) {
	b.WriteString(`<defs>
  <marker id="arrow-default" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"/></marker>
  <marker id="arrow-path" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#4f46e5"/></marker>
  <marker id="arrow-block" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#b91c1c"/></marker>
  <marker id="arrow-warn" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#d97706"/></marker>
</defs>
`)
}

func writeSVGRoutes(b *strings.Builder, nodes []positionedNode, edges []Edge) {
	positions := make(map[string]positionedNode, len(nodes))
	for _, node := range nodes {
		positions[node.ID] = node
	}
	for index, edge := range edges {
		from, okFrom := positions[edge.From]
		to, okTo := positions[edge.To]
		if !okFrom || !okTo {
			continue
		}
		x1, y1 := from.X+htmlNodeWidth, from.Y+htmlNodeHeight/2
		x2, y2 := to.X, to.Y+htmlNodeHeight/2
		if to.X < from.X {
			x1 = from.X
			x2 = to.X + htmlNodeWidth
		}
		mid := x1 + math.Max(72, math.Abs(x2-x1)/2)
		if x2 < x1 {
			mid = x1 - math.Max(72, math.Abs(x2-x1)/2)
		}
		if math.Abs(y2-y1) > htmlNodeGapY/2 {
			mid += float64((index%3)-1) * 22
		}
		className := "edge"
		if edge.Role != RoleDefault {
			className += " " + html.EscapeString(string(edge.Role))
		}
		fmt.Fprintf(b, "<path class=\"%s\" data-from=\"%s\" data-to=\"%s\" d=\"M %.1f %.1f C %.1f %.1f, %.1f %.1f, %.1f %.1f\"/>\n",
			className, html.EscapeString(edge.From), html.EscapeString(edge.To), x1, y1, mid, y1, mid, y2, x2, y2)
		if edge.Label != "" {
			labelX, labelY := edgeLabelPosition(x1, y1, x2, y2)
			fmt.Fprintf(b, "<text class=\"edge-label\" x=\"%.1f\" y=\"%.1f\">%s</text>\n", labelX, labelY, html.EscapeString(edge.Label))
		}
	}
}

func edgeLabelPosition(x1 float64, y1 float64, x2 float64, y2 float64) (float64, float64) {
	if math.Abs(y2-y1) > htmlNodeHeight {
		return (x1+x2)/2 + 18, (y1+y2)/2 - 10
	}
	return (x1 + x2) / 2, math.Min(y1, y2) - htmlEdgeLabelOffset
}

func writeSVGNodes(b *strings.Builder, nodes []positionedNode) {
	for _, node := range nodes {
		style := styleForRole(node.Role)
		fmt.Fprintf(b, "<g class=\"node\" data-id=\"%s\" data-role=\"%s\" transform=\"translate(%.1f %.1f)\">\n", html.EscapeString(node.ID), html.EscapeString(string(node.Role)), node.X, node.Y)
		fmt.Fprintf(b, "<rect width=\"%.0f\" height=\"%.0f\" rx=\"8\" fill=\"%s\" stroke=\"%s\"></rect>\n", htmlNodeWidth, htmlNodeHeight, style.Fill, style.Stroke)
		writeWrappedText(b, node.Label, "node-title", 14, 24, 26)
		kind := node.Kind
		if kind == "" {
			kind = string(node.Role)
		}
		fmt.Fprintf(b, "<text class=\"node-kind\" x=\"14\" y=\"58\">%s</text>\n", html.EscapeString(kind))
		b.WriteString("</g>\n")
	}
}

func writeWrappedText(b *strings.Builder, value string, className string, x float64, y float64, max int) {
	lines := wrapText(value, max, 2)
	for index, line := range lines {
		fmt.Fprintf(b, "<text class=\"%s\" x=\"%.1f\" y=\"%.1f\">%s</text>\n", className, x, y+float64(index*14), html.EscapeString(line))
	}
}

func layoutDiagram(diagram Diagram) []positionedNode {
	if len(diagram.FocusPaths) > 0 {
		return layoutFocusDiagram(diagram)
	}
	nodes := append([]Node{}, diagram.Nodes...)
	sort.SliceStable(nodes, func(i int, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	layers := assignLayers(nodes, diagram.FocusPaths)
	grouped := make(map[int][]Node)
	maxLayer := 0
	for _, node := range nodes {
		layer := layers[node.ID]
		grouped[layer] = append(grouped[layer], node)
		if layer > maxLayer {
			maxLayer = layer
		}
	}
	out := make([]positionedNode, 0, len(nodes))
	for layer := 0; layer <= maxLayer; layer++ {
		group := grouped[layer]
		sort.SliceStable(group, func(i int, j int) bool {
			return group[i].ID < group[j].ID
		})
		for row, node := range group {
			out = append(out, positionedNode{
				Node: node,
				X:    htmlCanvasPaddingX + float64(layer)*(htmlNodeWidth+htmlNodeGapX),
				Y:    htmlCanvasPaddingY + float64(row)*(htmlNodeHeight+46),
			})
		}
	}
	return out
}

func layoutFocusDiagram(diagram Diagram) []positionedNode {
	ordered := orderedFocusNodes(diagram)
	indexByID := make(map[string]int, len(ordered))
	for index, node := range ordered {
		indexByID[node.ID] = index
	}
	out := make([]positionedNode, 0, len(ordered))
	for index, node := range ordered {
		col, row := focusGridPosition(index)
		out = append(out, positionedNode{
			Node: node,
			X:    htmlCanvasPaddingX + float64(col)*(htmlNodeWidth+htmlNodeGapX),
			Y:    htmlCanvasPaddingY + float64(row)*(htmlNodeHeight+htmlNodeGapY),
		})
	}
	for _, node := range sortedUnplacedNodes(diagram.Nodes, indexByID) {
		index := len(out)
		col, row := focusGridPosition(index)
		out = append(out, positionedNode{
			Node: node,
			X:    htmlCanvasPaddingX + float64(col)*(htmlNodeWidth+htmlNodeGapX),
			Y:    htmlCanvasPaddingY + float64(row)*(htmlNodeHeight+htmlNodeGapY),
		})
	}
	return out
}

func orderedFocusNodes(diagram Diagram) []Node {
	byID := make(map[string]Node, len(diagram.Nodes))
	for _, node := range diagram.Nodes {
		byID[node.ID] = node
	}
	seen := make(map[string]bool, len(diagram.Nodes))
	out := make([]Node, 0, len(diagram.Nodes))
	for _, path := range diagram.FocusPaths {
		for _, id := range path {
			if seen[id] {
				continue
			}
			node, ok := byID[id]
			if !ok {
				continue
			}
			seen[id] = true
			out = append(out, node)
		}
	}
	return out
}

func sortedUnplacedNodes(nodes []Node, placed map[string]int) []Node {
	out := make([]Node, 0)
	for _, node := range nodes {
		if _, ok := placed[node.ID]; !ok {
			out = append(out, node)
		}
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func focusGridPosition(index int) (int, int) {
	row := index / htmlFocusColumns
	offset := index % htmlFocusColumns
	if row%2 == 1 {
		return htmlFocusColumns - 1 - offset, row
	}
	return offset, row
}

func assignLayers(nodes []Node, focusPaths [][]string) map[string]int {
	layers := make(map[string]int, len(nodes))
	if len(focusPaths) > 0 {
		for _, path := range focusPaths {
			for index, id := range path {
				if current, ok := layers[id]; !ok || index > current {
					layers[id] = index
				}
			}
		}
	}
	for _, node := range nodes {
		if _, ok := layers[node.ID]; !ok {
			layers[node.ID] = seedLayer(node.Role)
		}
	}
	return layers
}

func seedLayer(role Role) int {
	switch role {
	case RoleInternet, RolePublic, RolePrincipal:
		return 0
	case RoleWorkload, RolePolicy:
		return 1
	case RoleSensitive, RoleBlock, RoleWarn:
		return 2
	default:
		return 1
	}
}

func canvasSize(nodes []positionedNode) (float64, float64) {
	width := 960.0
	height := 640.0
	for _, node := range nodes {
		width = math.Max(width, node.X+htmlNodeWidth+htmlCanvasPaddingX)
		height = math.Max(height, node.Y+htmlNodeHeight+htmlCanvasPaddingY)
	}
	return width, height
}

func roleCounts(nodes []Node) map[Role]int {
	counts := make(map[Role]int)
	for _, node := range nodes {
		role := node.Role
		if role == "" {
			role = RoleDefault
		}
		counts[role]++
	}
	return counts
}

func sortedRoles(counts map[Role]int) []Role {
	roles := make([]Role, 0, len(counts))
	for role := range counts {
		roles = append(roles, role)
	}
	sort.SliceStable(roles, func(i int, j int) bool {
		return roleLabel(roles[i]) < roleLabel(roles[j])
	})
	return roles
}

func roleLabel(role Role) string {
	if role == "" {
		role = RoleDefault
	}
	return strings.ReplaceAll(string(role), "_", " ")
}

func wrapText(value string, maxChars int, maxLines int) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return []string{""}
	}
	words := strings.Fields(value)
	lines := make([]string, 0, maxLines)
	current := ""
	for _, word := range words {
		if current == "" {
			current = word
			continue
		}
		if len(current)+1+len(word) > maxChars {
			lines = append(lines, current)
			current = word
			if len(lines) == maxLines-1 {
				break
			}
			continue
		}
		current += " " + word
	}
	if current != "" && len(lines) < maxLines {
		lines = append(lines, current)
	}
	if len(lines) == 0 {
		lines = append(lines, value)
	}
	if len(words) > 0 && strings.Join(lines, " ") != value && len(lines) == maxLines {
		last := lines[len(lines)-1]
		if len(last) > maxChars-1 {
			last = last[:maxChars-1]
		}
		lines[len(lines)-1] = strings.TrimRight(last, ". ") + "..."
	}
	return lines
}

func diagramData(diagram Diagram) map[string]any {
	nodes := make([]map[string]any, 0, len(diagram.Nodes))
	for _, node := range diagram.Nodes {
		nodes = append(nodes, map[string]any{
			"id":       node.ID,
			"label":    node.Label,
			"kind":     node.Kind,
			"type":     node.Type,
			"role":     node.Role,
			"changed":  node.Changed,
			"decision": node.Decision,
			"severity": node.Severity,
			"details":  node.Details,
		})
	}
	return map[string]any{
		"title":       diagram.Title,
		"description": diagram.Description,
		"nodes":       nodes,
	}
}

func htmlScript() string {
	return `
const nodes = Array.from(document.querySelectorAll('.node'));
const edges = Array.from(document.querySelectorAll('.edge'));
const byId = new Map(CHANGEGATE_DIAGRAM.nodes.map((node) => [node.id, node]));
const search = document.getElementById('search');
const checks = Array.from(document.querySelectorAll('[data-role][type="checkbox"]'));
const details = document.getElementById('details');

function activeRoles() {
  return new Set(checks.filter((input) => input.checked).map((input) => input.dataset.role));
}

function applyFilters() {
  const query = search.value.trim().toLowerCase();
  const roles = activeRoles();
  const visible = new Set();
  nodes.forEach((element) => {
    const node = byId.get(element.dataset.id);
    const text = [node.id, node.label, node.kind, node.type, node.role].join(' ').toLowerCase();
    const show = roles.has(element.dataset.role) && (!query || text.includes(query));
    element.classList.toggle('hidden', !show);
    if (show) visible.add(node.id);
  });
  edges.forEach((edge) => {
    const show = visible.has(edge.dataset.from) && visible.has(edge.dataset.to);
    edge.classList.toggle('hidden', !show);
  });
}

function selectNode(id) {
  nodes.forEach((node) => node.classList.toggle('selected', node.dataset.id === id));
  const node = byId.get(id);
  const detailItems = (node.details || []).map((item) => '<li>' + escapeHTML(item) + '</li>').join('');
  details.innerHTML =
    '<h2>' + escapeHTML(node.label || node.id) + '</h2>' +
    '<p class="muted">' + escapeHTML(node.id) + '</p>' +
    '<dl>' +
      '<dt>Role</dt><dd>' + escapeHTML(node.role || 'default') + '</dd>' +
      '<dt>Kind</dt><dd>' + escapeHTML(node.kind || 'unknown') + '</dd>' +
      '<dt>Type</dt><dd>' + escapeHTML(node.type || 'n/a') + '</dd>' +
      '<dt>Changed</dt><dd>' + (node.changed ? 'yes' : 'no') + '</dd>' +
      '<dt>Decision</dt><dd>' + escapeHTML(node.decision || 'n/a') + '</dd>' +
      '<dt>Severity</dt><dd>' + escapeHTML(node.severity || 'n/a') + '</dd>' +
    '</dl>' +
    '<h3>Evidence</h3>' +
    '<ul>' + (detailItems || '<li>No additional details.</li>') + '</ul>';
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

search.addEventListener('input', applyFilters);
checks.forEach((input) => input.addEventListener('change', applyFilters));
nodes.forEach((node) => node.addEventListener('click', () => selectNode(node.dataset.id)));
applyFilters();
if (nodes[0]) selectNode(nodes[0].dataset.id);
`
}
