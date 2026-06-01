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
  overflow: visible;
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
.graph-tools {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}
.tool-button {
  appearance: none;
  border: 1px solid var(--line);
  background: #fff;
  border-radius: 8px;
  color: #334155;
  cursor: pointer;
  font: inherit;
  font-weight: 650;
  min-height: 34px;
}
.tool-button:hover { border-color: #94a3b8; color: var(--ink); }
.tool-note { color: var(--muted); font-size: 12px; margin: -2px 0 0; }
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
svg { min-width: 100%; display: block; cursor: grab; touch-action: none; user-select: none; }
svg.panning { cursor: grabbing; }
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
.node { cursor: grab; transition: opacity .15s ease; }
.node.dragging { cursor: grabbing; }
.node rect { stroke-width: 2; filter: drop-shadow(0 10px 15px rgba(15, 23, 42, .08)); }
.node text { pointer-events: none; }
.node-title { font-weight: 700; fill: #0f172a; font-size: 12px; }
.node-kind { fill: #64748b; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; }
.node.selected rect { stroke: #111827; stroke-width: 3; }
.hidden { opacity: .08; pointer-events: none; }
.details h2 { margin: 0 0 8px; font-size: 18px; }
.details .muted { color: var(--muted); }
.details dl { display: grid; grid-template-columns: 130px 1fr; gap: 6px 14px; margin: 16px 0; max-width: 920px; }
.details dt { color: var(--muted); }
.details dd { margin: 0; word-break: break-word; }
.details ul { padding-left: 18px; margin: 8px 0; }
.details-grid {
  display: grid;
  grid-template-columns: minmax(260px, 420px) minmax(280px, 1fr);
  gap: 18px 32px;
}
.detail-card {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px;
  background: #f8fafc;
}
.detail-card h3 { margin: 0 0 8px; font-size: 14px; }
.detail-card p { margin: 0; color: #334155; }
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
	b.WriteString("<g id=\"viewport\">\n")
	writeSVGRoutes(&b, layout, diagram.Edges)
	writeSVGNodes(&b, layout)
	b.WriteString("</g>\n")
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
	b.WriteString(`<div class="graph-tools" aria-label="Graph controls">
<button class="tool-button" type="button" data-action="zoom-in">Zoom +</button>
<button class="tool-button" type="button" data-action="zoom-out">Zoom -</button>
<button class="tool-button" type="button" data-action="reset">Reset</button>
</div>
<p class="tool-note">Drag the canvas to pan. Drag nodes to rearrange. Hold Ctrl/Cmd and scroll to zoom.</p>
`)
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
			fmt.Fprintf(b, "<text class=\"edge-label\" data-from=\"%s\" data-to=\"%s\" x=\"%.1f\" y=\"%.1f\">%s</text>\n", html.EscapeString(edge.From), html.EscapeString(edge.To), labelX, labelY, html.EscapeString(edge.Label))
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
			"summary":  nodeSummary(node),
			"roleText": roleDescription(node.Role),
			"kindText": kindDescription(node.Kind),
		})
	}
	edges := make([]map[string]any, 0, len(diagram.Edges))
	for _, edge := range diagram.Edges {
		edges = append(edges, map[string]any{
			"from":       edge.From,
			"to":         edge.To,
			"label":      edge.Label,
			"role":       edge.Role,
			"confidence": edge.Confidence,
			"details":    edge.Details,
		})
	}
	return map[string]any{
		"title":       diagram.Title,
		"description": diagram.Description,
		"nodes":       nodes,
		"edges":       edges,
		"nodeWidth":   htmlNodeWidth,
		"nodeHeight":  htmlNodeHeight,
	}
}

func nodeSummary(node Node) string {
	role := roleDescription(node.Role)
	kind := kindDescription(node.Kind)
	switch {
	case role != "" && kind != "":
		return role + " " + kind
	case role != "":
		return role
	case kind != "":
		return kind
	default:
		return "Graph node included in the rendered infrastructure relationship view."
	}
}

func roleDescription(role Role) string {
	switch role {
	case RolePublic:
		return "Public entrypoint: this node can receive traffic from outside the private network."
	case RoleInternet:
		return "Internet source: synthetic node representing external public access."
	case RoleWorkload:
		return "Workload: compute or service that can process requests and connect downstream."
	case RoleSensitive:
		return "Sensitive asset: datastore, secret, or key that can increase blast radius."
	case RolePrincipal:
		return "Principal: IAM identity or role involved in an access path."
	case RolePolicy:
		return "Policy: IAM policy or permission grant involved in access."
	case RoleNetwork:
		return "Network boundary: security group, subnet, route, or similar connectivity control."
	case RolePath:
		return "Path node: intermediate resource on the highlighted relationship path."
	case RoleBlock:
		return "Blocking risk target: this node participates in a path that can block deployment."
	case RoleWarn:
		return "Warning risk node: this node participates in a path that should be reviewed."
	case RoleAllow:
		return "Allowed node: this node participates in a reviewed path that is not blocking."
	case RoleChanged:
		return "Changed resource: Terraform/OpenTofu plans to create, update, replace, or delete this node."
	default:
		return "Resource node: included for graph context."
	}
}

func kindDescription(kind string) string {
	switch kind {
	case "public_entrypoint":
		return "It is classified as an ingress point such as a load balancer, public endpoint, or internet-facing service."
	case "workload":
		return "It is classified as compute or application runtime, such as ECS, Lambda, EC2, or Kubernetes workload."
	case "data_store":
		return "It is classified as a datastore, so reachability can indicate data exposure."
	case "secret":
		return "It is classified as a secret or credential store."
	case "kms_key":
		return "It is classified as a KMS key or cryptographic control."
	case "principal":
		return "It is classified as an IAM principal."
	case "policy":
		return "It is classified as an IAM policy or permission relationship."
	case "network_boundary":
		return "It is classified as a network boundary or routing control."
	case "unknown":
		return "ChangeGate preserved this resource in the path even though it does not have a more specific security classification yet."
	case "attack_path":
		return "It is part of a detected attack path sequence."
	default:
		if kind == "" {
			return "No graph kind was assigned."
		}
		return "Graph kind: " + strings.ReplaceAll(kind, "_", " ") + "."
	}
}

func htmlScript() string {
	return `
const NODE_WIDTH = CHANGEGATE_DIAGRAM.nodeWidth || 230;
const NODE_HEIGHT = CHANGEGATE_DIAGRAM.nodeHeight || 72;
const nodes = Array.from(document.querySelectorAll('.node'));
const edges = Array.from(document.querySelectorAll('.edge'));
const edgeLabels = Array.from(document.querySelectorAll('.edge-label'));
const svg = document.getElementById('graph');
const viewport = document.getElementById('viewport');
const byId = new Map(CHANGEGATE_DIAGRAM.nodes.map((node) => [node.id, node]));
const graphEdges = CHANGEGATE_DIAGRAM.edges || [];
const search = document.getElementById('search');
const checks = Array.from(document.querySelectorAll('[data-role][type="checkbox"]'));
const details = document.getElementById('details');
const positions = new Map(nodes.map((node) => {
  const match = /translate\(([-0-9.]+)\s+([-0-9.]+)\)/.exec(node.getAttribute('transform') || '');
  return [node.dataset.id, { x: Number(match && match[1] || 0), y: Number(match && match[2] || 0) }];
}));
let transform = { x: 0, y: 0, scale: 1 };
let activeDrag = null;
let activePan = null;

function capturePointer(element, pointerId) {
  if (!element || !element.setPointerCapture) return;
  try {
    element.setPointerCapture(pointerId);
  } catch (_error) {
    // Synthetic pointer events used by browser automation may not have an active pointer.
  }
}

function releasePointer(element, pointerId) {
  if (!element || !element.hasPointerCapture || !element.releasePointerCapture) return;
  if (element.hasPointerCapture(pointerId)) element.releasePointerCapture(pointerId);
}

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
  edgeLabels.forEach((label) => {
    const show = visible.has(label.dataset.from) && visible.has(label.dataset.to);
    label.classList.toggle('hidden', !show);
  });
}

function selectNode(id) {
  nodes.forEach((node) => node.classList.toggle('selected', node.dataset.id === id));
  const node = byId.get(id);
  const connected = connectedEdges(id);
  const detailItems = (node.details || []).map((item) => '<li>' + escapeHTML(item) + '</li>').join('');
  const connectedItems = connected.map((edge) => '<li><strong>' + escapeHTML(edge.direction) + '</strong> ' + escapeHTML(edge.label || 'relationship') + ' ' + escapeHTML(edge.other) + formatConfidence(edge) + '</li>').join('');
  const statusRows = [
    rowHTML('Role', node.role || 'default'),
    rowHTML('Kind', node.kind || 'unknown'),
    rowHTML('Type', node.type || 'n/a'),
    rowHTML('Changed', node.changed ? 'yes' : 'no')
  ];
  if (node.decision) statusRows.push(rowHTML('Decision', node.decision));
  if (node.severity) statusRows.push(rowHTML('Severity', node.severity));
  details.innerHTML =
    '<h2>' + escapeHTML(node.label || node.id) + '</h2>' +
    '<p class="muted">' + escapeHTML(node.id) + '</p>' +
    '<div class="details-grid">' +
      '<div>' +
        '<dl>' + statusRows.join('') + '</dl>' +
        '<div class="detail-card"><h3>What this means</h3><p>' + escapeHTML(node.summary || node.roleText || 'This node is part of the rendered graph evidence.') + '</p></div>' +
      '</div>' +
      '<div>' +
        '<div class="detail-card"><h3>Why it appears here</h3><p>' + escapeHTML(whyIncluded(node)) + '</p></div>' +
        '<h3>Connected relationships</h3>' +
        '<ul>' + (connectedItems || '<li>No connected relationships were included in this view.</li>') + '</ul>' +
        '<h3>Evidence</h3>' +
        '<ul>' + (detailItems || '<li>No additional evidence details.</li>') + '</ul>' +
      '</div>' +
    '</div>';
}

function rowHTML(label, value) {
  return '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value) + '</dd>';
}

function connectedEdges(id) {
  return graphEdges.flatMap((edge) => {
    if (edge.from === id) return [{ direction: 'outbound to', other: edge.to, label: edge.label, confidence: edge.confidence }];
    if (edge.to === id) return [{ direction: 'inbound from', other: edge.from, label: edge.label, confidence: edge.confidence }];
    return [];
  });
}

function formatConfidence(edge) {
  return edge.confidence ? ' (' + escapeHTML(edge.confidence) + ' confidence)' : '';
}

function whyIncluded(node) {
  if (node.role === 'public' || node.role === 'internet') return 'This is the public side of the path. It helps reviewers see where exposure starts.';
  if (node.role === 'workload') return 'This workload is on the route between the entrypoint and downstream assets.';
  if (node.role === 'sensitive' || node.role === 'block') return 'This is the downstream asset or risk target that makes the path important.';
  if (node.role === 'network') return 'This node represents connectivity control that allows or shapes reachability.';
  if (node.role === 'path') return 'This intermediate node keeps the path explainable instead of hiding routing or attachment hops.';
  return 'This node is connected to the highlighted graph evidence.';
}

function updateViewport() {
  viewport.setAttribute('transform', 'translate(' + transform.x + ' ' + transform.y + ') scale(' + transform.scale + ')');
}

function graphPoint(event) {
  const point = svg.createSVGPoint();
  point.x = event.clientX;
  point.y = event.clientY;
  const base = point.matrixTransform(svg.getScreenCTM().inverse());
  return {
    x: (base.x - transform.x) / transform.scale,
    y: (base.y - transform.y) / transform.scale
  };
}

function setNodePosition(id, x, y) {
  positions.set(id, { x, y });
  const element = nodes.find((node) => node.dataset.id === id);
  if (element) element.setAttribute('transform', 'translate(' + x.toFixed(1) + ' ' + y.toFixed(1) + ')');
  updateConnectedGeometry(id);
}

function updateConnectedGeometry(id) {
  edges.forEach((edge, index) => {
    if (edge.dataset.from !== id && edge.dataset.to !== id) return;
    updateEdgeGeometry(edge, edgeLabels[index], index);
  });
}

function updateEdgeGeometry(edge, label, index) {
  const from = positions.get(edge.dataset.from);
  const to = positions.get(edge.dataset.to);
  if (!from || !to) return;
  let x1 = from.x + NODE_WIDTH;
  let y1 = from.y + NODE_HEIGHT / 2;
  let x2 = to.x;
  let y2 = to.y + NODE_HEIGHT / 2;
  if (to.x < from.x) {
    x1 = from.x;
    x2 = to.x + NODE_WIDTH;
  }
  let mid = x1 + Math.max(72, Math.abs(x2 - x1) / 2);
  if (x2 < x1) mid = x1 - Math.max(72, Math.abs(x2 - x1) / 2);
  if (Math.abs(y2 - y1) > 75) mid += ((index % 3) - 1) * 22;
  edge.setAttribute('d', 'M ' + x1.toFixed(1) + ' ' + y1.toFixed(1) + ' C ' + mid.toFixed(1) + ' ' + y1.toFixed(1) + ', ' + mid.toFixed(1) + ' ' + y2.toFixed(1) + ', ' + x2.toFixed(1) + ' ' + y2.toFixed(1));
  if (label) {
    const labelX = (x1 + x2) / 2 + (Math.abs(y2 - y1) > NODE_HEIGHT ? 18 : 0);
    const labelY = Math.abs(y2 - y1) > NODE_HEIGHT ? (y1 + y2) / 2 - 10 : Math.min(y1, y2) - 18;
    label.setAttribute('x', labelX.toFixed(1));
    label.setAttribute('y', labelY.toFixed(1));
  }
}

function zoomBy(factor) {
  transform.scale = Math.min(2.5, Math.max(0.45, transform.scale * factor));
  updateViewport();
}

function resetView() {
  transform = { x: 0, y: 0, scale: 1 };
  updateViewport();
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

document.querySelector('[data-action="zoom-in"]').addEventListener('click', () => zoomBy(1.15));
document.querySelector('[data-action="zoom-out"]').addEventListener('click', () => zoomBy(0.87));
document.querySelector('[data-action="reset"]').addEventListener('click', resetView);
svg.addEventListener('wheel', (event) => {
  if (!event.ctrlKey && !event.metaKey) return;
  event.preventDefault();
  zoomBy(event.deltaY < 0 ? 1.08 : 0.92);
}, { passive: false });
svg.addEventListener('pointerdown', (event) => {
  const node = event.target.closest && event.target.closest('.node');
  if (node) {
    const start = graphPoint(event);
    const current = positions.get(node.dataset.id);
    activeDrag = { id: node.dataset.id, dx: start.x - current.x, dy: start.y - current.y, element: node };
    node.classList.add('dragging');
    capturePointer(node, event.pointerId);
    selectNode(node.dataset.id);
    event.stopPropagation();
    return;
  }
  const point = { x: event.clientX, y: event.clientY };
  activePan = { x: point.x, y: point.y, tx: transform.x, ty: transform.y, element: svg };
  svg.classList.add('panning');
  capturePointer(svg, event.pointerId);
});
svg.addEventListener('pointermove', (event) => {
  if (activeDrag) {
    const point = graphPoint(event);
    setNodePosition(activeDrag.id, point.x - activeDrag.dx, point.y - activeDrag.dy);
    return;
  }
  if (activePan) {
    transform.x = activePan.tx + (event.clientX - activePan.x);
    transform.y = activePan.ty + (event.clientY - activePan.y);
    updateViewport();
  }
});
svg.addEventListener('pointerup', (event) => {
  if (activeDrag) {
    const node = nodes.find((element) => element.dataset.id === activeDrag.id);
    if (node) node.classList.remove('dragging');
    releasePointer(activeDrag.element, event.pointerId);
  }
  if (activePan) {
    releasePointer(activePan.element, event.pointerId);
  }
  activeDrag = null;
  activePan = null;
  svg.classList.remove('panning');
});
svg.addEventListener('pointercancel', () => {
  activeDrag = null;
  activePan = null;
  svg.classList.remove('panning');
  nodes.forEach((node) => node.classList.remove('dragging'));
});
search.addEventListener('input', applyFilters);
checks.forEach((input) => input.addEventListener('change', applyFilters));
nodes.forEach((node) => node.addEventListener('click', () => selectNode(node.dataset.id)));
edges.forEach((edge, index) => updateEdgeGeometry(edge, edgeLabels[index], index));
updateViewport();
applyFilters();
if (nodes[0]) selectNode(nodes[0].dataset.id);
`
}
