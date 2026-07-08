package architecture

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/graph"
)

const (
	mapResourceWidth  = 168.0
	mapResourceHeight = 64.0
	mapCardGapX       = 18.0
	mapCardGapY       = 18.0
	mapSectionPadding = 28.0
	mapHeaderHeight   = 34.0
)

type mapNode struct {
	ID         string            `json:"id"`
	Label      string            `json:"label"`
	Kind       string            `json:"kind"`
	Type       string            `json:"type"`
	Service    string            `json:"service,omitempty"`
	Role       string            `json:"role"`
	Icon       string            `json:"icon"`
	Parent     string            `json:"parent,omitempty"`
	Details    []string          `json:"details,omitempty"`
	Properties []mapProperty     `json:"properties,omitempty"`
	Tags       []mapProperty     `json:"tags,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	X          float64           `json:"x"`
	Y          float64           `json:"y"`
	Width      float64           `json:"width"`
	Height     float64           `json:"height"`
}

type mapProperty struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Group string `json:"group,omitempty"`
}

type mapGroup struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Kind     string   `json:"kind"`
	Parent   string   `json:"parent,omitempty"`
	X        float64  `json:"x"`
	Y        float64  `json:"y"`
	Width    float64  `json:"width"`
	Height   float64  `json:"height"`
	Children []string `json:"children,omitempty"`
}

type mapEdge struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Label      string   `json:"label"`
	Confidence string   `json:"confidence,omitempty"`
	Details    []string `json:"details,omitempty"`
}

type mapData struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Summary     Summary    `json:"summary"`
	Groups      []mapGroup `json:"groups"`
	Nodes       []mapNode  `json:"nodes"`
	Edges       []mapEdge  `json:"edges"`
	Width       float64    `json:"width"`
	Height      float64    `json:"height"`
}

// RenderHTML renders a self-contained AWS architecture map.
func RenderHTML(snapshot cloudcontext.Snapshot, g *graph.Graph, summary Summary) []byte {
	data := buildMapData(snapshot, g, summary)
	encoded, _ := json.Marshal(data)
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<link rel=\"icon\" href=\"data:,\">\n")
	fmt.Fprintf(&b, "<title>%s</title>\n", html.EscapeString(data.Title))
	b.WriteString(mapStyles())
	b.WriteString("</head>\n<body>\n")
	fmt.Fprintf(&b, "<header><h1>%s</h1><p>%s</p></header>\n", html.EscapeString(data.Title), html.EscapeString(data.Description))
	b.WriteString(`<main class="shell">
<button id="controls-toggle" class="rail-toggle controls-toggle" type="button" aria-expanded="true" aria-controls="controls">Hide controls</button>
<aside>
  <div id="controls" class="controls-panel">
  <div class="toolbar">
    <input id="search" class="search" type="search" placeholder="Filter resources" autocomplete="off">
    <div class="buttons" aria-label="Map controls">
      <button type="button" data-action="zoom-in">Zoom +</button>
      <button type="button" data-action="zoom-out">Zoom -</button>
      <button type="button" data-action="reset">Reset</button>
    </div>
    <div class="buttons layout-buttons" aria-label="Layout controls">
      <button type="button" data-action="download-layout">Save layout</button>
      <button type="button" data-action="load-layout">Load layout</button>
      <button type="button" data-action="expand-groups">Expand all</button>
    </div>
    <input id="layout-file" type="file" accept="application/json,.json" hidden>
    <p class="hint">Drag the canvas to pan. Hold Ctrl/Cmd and scroll to zoom.</p>
  </div>
  <label class="toggle-row"><input id="edge-label-toggle" type="checkbox"> Show relationship labels</label>
  <div id="legend" class="legend"></div>
  <div class="inventory-panel">
    <div class="panel-title">Inventory</div>
    <div id="inventory" class="inventory" aria-label="Architecture inventory"></div>
  </div>
  <div class="metrics">
    <div><strong id="metric-nodes"></strong><span>resources</span></div>
    <div><strong id="metric-edges"></strong><span>relationships</span></div>
    <div><strong id="metric-public"></strong><span>public</span></div>
    <div><strong id="metric-sensitive"></strong><span>sensitive</span></div>
  </div>
  </div>
</aside>
<section class="canvas-wrap">
`)
	fmt.Fprintf(&b, "<svg id=\"map\" viewBox=\"0 0 %.0f %.0f\" width=\"%.0f\" height=\"%.0f\" role=\"img\" aria-label=\"%s\"><g id=\"viewport\"></g></svg>\n", data.Width, data.Height, data.Width, data.Height, html.EscapeString(data.Title))
	b.WriteString(`<div class="minimap" aria-label="Map overview"><svg id="minimap" viewBox="0 0 220 150" width="220" height="150"><g id="minimap-content"></g><rect id="minimap-view" class="minimap-view" x="0" y="0" width="1" height="1"></rect></svg></div>
`)
	b.WriteString(`</section>
<aside id="details" class="details" aria-label="Resource details" aria-hidden="true">
  <div class="details-empty">
    <button id="details-close" class="icon-button" type="button" aria-label="Close details">&times;</button>
    <h2>Select a resource</h2>
    <p>Click a resource or container to inspect identity, placement, and relationships.</p>
  </div>
</aside>
</main>
`)
	fmt.Fprintf(&b, "<script>const CHANGEGATE_ARCHITECTURE=%s;\n", encoded)
	b.WriteString(mapScript())
	b.WriteString("</script>\n</body>\n</html>\n")
	return []byte(b.String())
}

func buildMapData(snapshot cloudcontext.Snapshot, g *graph.Graph, summary Summary) mapData {
	if g == nil {
		g = &graph.Graph{Nodes: map[graph.ResourceID]*graph.Node{}}
	}
	builder := newMapBuilder(snapshot, g, summary)
	builder.layout()
	return mapData{
		Title:       Title(summary.View),
		Description: Description(snapshot, summary.View, summary.Truncated),
		Summary:     summary,
		Groups:      builder.groups,
		Nodes:       builder.nodes,
		Edges:       builder.edges(),
		Width:       builder.width,
		Height:      builder.height,
	}
}

type mapBuilder struct {
	snapshot cloudcontext.Snapshot
	graph    *graph.Graph
	summary  Summary
	groups   []mapGroup
	nodes    []mapNode
	width    float64
	height   float64
	placed   map[string]bool
}

func newMapBuilder(snapshot cloudcontext.Snapshot, g *graph.Graph, summary Summary) *mapBuilder {
	return &mapBuilder{
		snapshot: snapshot,
		graph:    g,
		summary:  summary,
		placed:   make(map[string]bool),
	}
}

func (b *mapBuilder) layout() {
	const (
		startX     = 56.0
		startY     = 54.0
		columnGap  = 36.0
		regionGap  = 34.0
		sectionGap = 26.0
	)
	accountID := firstNonEmpty(b.snapshot.Account.ID, "unknown")
	accountLabel := "AWS account " + accountID
	regionIDs := b.regionIDs()
	if len(regionIDs) == 0 {
		regionIDs = []string{"global"}
	}
	currentY := startY + mapHeaderHeight + mapSectionPadding
	maxWidth := 1180.0
	accountChildren := make([]string, 0, len(regionIDs)+2)
	accountGroup := mapGroup{ID: accountNodeIDPrefix + accountID, Label: accountLabel, Kind: "account", X: startX, Y: startY}
	b.groups = append(b.groups, accountGroup)

	for _, regionID := range regionIDs {
		regionName := strings.TrimPrefix(regionID, regionNodeIDPrefix)
		regionX := startX + mapSectionPadding
		regionY := currentY
		vpcGroups := b.vpcIDs(regionName)
		regionChildren := make([]string, 0)
		sectionY := regionY + mapHeaderHeight + mapSectionPadding
		regionWidth := 0.0

		if len(vpcGroups) == 0 {
			w, h, childID := b.layoutResourceSection("regional-"+regionName, "Regional services", "services", regionID, regionX+mapSectionPadding, sectionY, b.nodesForRegionWithoutVPC(regionName), 4)
			regionChildren = append(regionChildren, childID)
			sectionY += h + sectionGap
			regionWidth = math.Max(regionWidth, w+mapSectionPadding*2)
		} else {
			vpcX := regionX + mapSectionPadding
			vpcY := sectionY
			for _, vpcID := range vpcGroups {
				vpcW, vpcH, childID := b.layoutVPC(vpcID, regionName, vpcX, vpcY)
				regionChildren = append(regionChildren, childID)
				regionWidth = math.Max(regionWidth, vpcX-regionX+vpcW+mapSectionPadding)
				vpcX += vpcW + columnGap
				if vpcX-regionX > 980 {
					vpcX = regionX + mapSectionPadding
					vpcY += vpcH + sectionGap
					sectionY = vpcY
				}
				sectionY = math.Max(sectionY, vpcY+vpcH+sectionGap)
			}
			if regional := b.nodesForRegionWithoutVPC(regionName); len(regional) > 0 {
				w, h, childID := b.layoutResourceSection("regional-"+regionName, "Regional services", "services", regionID, regionX+mapSectionPadding, sectionY, regional, 4)
				regionChildren = append(regionChildren, childID)
				sectionY += h + sectionGap
				regionWidth = math.Max(regionWidth, w+mapSectionPadding*2)
			}
		}

		regionHeight := sectionY - regionY + mapSectionPadding
		regionWidth = math.Max(regionWidth, 520)
		b.groups = append(b.groups, mapGroup{
			ID:       regionID,
			Label:    firstNonEmpty(regionName, "Global"),
			Kind:     "region",
			Parent:   accountGroup.ID,
			X:        regionX,
			Y:        regionY,
			Width:    regionWidth,
			Height:   regionHeight,
			Children: regionChildren,
		})
		accountChildren = append(accountChildren, regionID)
		currentY += regionHeight + regionGap
		maxWidth = math.Max(maxWidth, regionX+regionWidth+startX)
	}

	if globalNodes := b.globalNodes(); len(globalNodes) > 0 {
		w, h, childID := b.layoutResourceSection("global-services", "Global services", "services", "global", startX+mapSectionPadding, currentY, globalNodes, 4)
		b.groups = append(b.groups, mapGroup{
			ID:       "global",
			Label:    "Global services",
			Kind:     "global",
			Parent:   accountGroup.ID,
			X:        startX + mapSectionPadding,
			Y:        currentY,
			Width:    w,
			Height:   h,
			Children: []string{childID},
		})
		accountChildren = append(accountChildren, "global")
		currentY += h + regionGap
		maxWidth = math.Max(maxWidth, startX+w+mapSectionPadding)
	}

	if unplaced := b.unplacedNodes(); len(unplaced) > 0 {
		w, h, childID := b.layoutResourceSection("unplaced", "Unplaced resources", "services", "unplaced-root", startX+mapSectionPadding, currentY, unplaced, 4)
		b.groups = append(b.groups, mapGroup{
			ID:       "unplaced-root",
			Label:    "Unplaced resources",
			Kind:     "global",
			Parent:   accountGroup.ID,
			X:        startX + mapSectionPadding,
			Y:        currentY,
			Width:    w,
			Height:   h,
			Children: []string{childID},
		})
		accountChildren = append(accountChildren, "unplaced-root")
		currentY += h + regionGap
		maxWidth = math.Max(maxWidth, startX+w+mapSectionPadding)
	}

	for index := range b.groups {
		if b.groups[index].ID == accountGroup.ID {
			b.groups[index].Width = maxWidth - startX
			b.groups[index].Height = currentY - startY + mapSectionPadding
			b.groups[index].Children = accountChildren
			break
		}
	}
	b.width = maxWidth + 80
	b.height = currentY + 80
	sort.SliceStable(b.groups, func(i int, j int) bool {
		if b.groups[i].Parent != b.groups[j].Parent {
			return b.groups[i].Parent < b.groups[j].Parent
		}
		return b.groups[i].ID < b.groups[j].ID
	})
	sort.SliceStable(b.nodes, func(i int, j int) bool { return b.nodes[i].ID < b.nodes[j].ID })
}

func (b *mapBuilder) layoutVPC(vpcID graph.ResourceID, region string, x float64, y float64) (float64, float64, string) {
	vpcNode := b.graph.Nodes[vpcID]
	vpcLabel := "VPC"
	if vpcNode != nil {
		vpcLabel = labelForNode(vpcNode)
		if cidr := stringValue(vpcNode.Values, "cidr_block"); cidr != "" {
			vpcLabel += " (" + cidr + ")"
		}
	}
	subnetIDs := b.subnetIDs(vpcID, region)
	children := make([]string, 0, len(subnetIDs)+1)
	contentY := y + mapHeaderHeight + mapSectionPadding
	contentX := x + mapSectionPadding
	maxWidth := 0.0
	totalHeight := mapHeaderHeight + mapSectionPadding
	if len(subnetIDs) == 0 {
		w, h, childID := b.layoutResourceSection("vpc-services-"+string(vpcID), "VPC resources", "network-resources", string(vpcID), contentX, contentY, b.nodesForVPCWithoutSubnet(vpcID, region), 2)
		children = append(children, childID)
		maxWidth = math.Max(maxWidth, w+mapSectionPadding*2)
		totalHeight += h + mapSectionPadding
	} else {
		subnetX := contentX
		rowHeight := 0.0
		for index, subnetID := range subnetIDs {
			w, h, childID := b.layoutSubnet(subnetID, string(vpcID), subnetX, contentY)
			children = append(children, childID)
			rowHeight = math.Max(rowHeight, h)
			maxWidth = math.Max(maxWidth, subnetX-x+w+mapSectionPadding)
			if index%2 == 1 {
				subnetX = contentX
				contentY += rowHeight + 22
				totalHeight += rowHeight + 22
				rowHeight = 0
			} else {
				subnetX += w + 22
			}
		}
		totalHeight += rowHeight + mapSectionPadding
		if vpcOnly := b.nodesForVPCWithoutSubnet(vpcID, region); len(vpcOnly) > 0 {
			contentY += rowHeight + 22
			w, h, childID := b.layoutResourceSection("vpc-services-"+string(vpcID), "VPC resources", "network-resources", string(vpcID), contentX, contentY, vpcOnly, 3)
			children = append(children, childID)
			maxWidth = math.Max(maxWidth, w+mapSectionPadding*2)
			totalHeight += h + 22
		}
	}
	width := math.Max(maxWidth, 420)
	height := math.Max(totalHeight, 240)
	b.groups = append(b.groups, mapGroup{
		ID:       string(vpcID),
		Label:    vpcLabel,
		Kind:     "vpc",
		Parent:   regionNodeIDPrefix + region,
		X:        x,
		Y:        y,
		Width:    width,
		Height:   height,
		Children: children,
	})
	return width, height, string(vpcID)
}

func (b *mapBuilder) layoutSubnet(subnetID graph.ResourceID, parent string, x float64, y float64) (float64, float64, string) {
	node := b.graph.Nodes[subnetID]
	label := labelForNode(node)
	if cidr := stringValue(node.Values, "cidr_block"); cidr != "" {
		label += " (" + cidr + ")"
	}
	nodes := b.nodesForSubnet(subnetID)
	w, h, sectionID := b.layoutResourceSection("subnet-"+string(subnetID), label, "subnet", parent, x, y, nodes, 2)
	for index := range b.groups {
		if b.groups[index].ID == sectionID {
			b.groups[index].Kind = subnetKind(node)
			break
		}
	}
	return w, h, sectionID
}

func (b *mapBuilder) layoutResourceSection(id string, label string, kind string, parent string, x float64, y float64, ids []graph.ResourceID, columns int) (float64, float64, string) {
	if columns <= 0 {
		columns = 2
	}
	rows := int(math.Ceil(float64(maxInt(1, len(ids))) / float64(columns)))
	width := mapSectionPadding*2 + float64(columns)*mapResourceWidth + float64(columns-1)*mapCardGapX
	height := mapHeaderHeight + mapSectionPadding*2 + float64(rows)*mapResourceHeight + float64(rows-1)*mapCardGapY
	children := make([]string, 0, len(ids))
	for index, idValue := range ids {
		node := b.graph.Nodes[idValue]
		col := index % columns
		row := index / columns
		b.nodes = append(b.nodes, mapNode{
			ID:         string(idValue),
			Label:      labelForNode(node),
			Kind:       displayKind(node),
			Type:       nodeType(node),
			Service:    serviceLabelForNode(node),
			Role:       roleForNode(node),
			Icon:       iconForNode(node),
			Parent:     id,
			Details:    detailsForNode(node),
			Properties: propertiesForNode(node),
			Tags:       tagsForNode(node),
			Metadata:   metadataForNode(node),
			X:          x + mapSectionPadding + float64(col)*(mapResourceWidth+mapCardGapX),
			Y:          y + mapHeaderHeight + mapSectionPadding + float64(row)*(mapResourceHeight+mapCardGapY),
			Width:      mapResourceWidth,
			Height:     mapResourceHeight,
		})
		children = append(children, string(idValue))
		b.placed[string(idValue)] = true
	}
	b.groups = append(b.groups, mapGroup{
		ID:       id,
		Label:    label,
		Kind:     kind,
		Parent:   parent,
		X:        x,
		Y:        y,
		Width:    width,
		Height:   height,
		Children: children,
	})
	return width, height, id
}

func (b *mapBuilder) edges() []mapEdge {
	nodeIDs := make(map[string]bool, len(b.nodes))
	for _, node := range b.nodes {
		nodeIDs[node.ID] = true
	}
	edges := make([]mapEdge, 0)
	seen := make(map[string]bool)
	for _, edge := range b.graph.Edges {
		if !nodeIDs[string(edge.From)] || !nodeIDs[string(edge.To)] || edge.Type == graph.EdgeContainedIn {
			continue
		}
		key := string(edge.From) + "\x00" + string(edge.To) + "\x00" + string(edge.Type)
		if seen[key] {
			continue
		}
		seen[key] = true
		edges = append(edges, mapEdge{
			From:       string(edge.From),
			To:         string(edge.To),
			Label:      humanize(string(edge.Type)),
			Confidence: string(edge.Confidence),
			Details:    []string{fmt.Sprintf("%s -> %s", edge.From, edge.To)},
		})
	}
	sort.SliceStable(edges, func(i int, j int) bool {
		left := edges[i].From + "\x00" + edges[i].To + "\x00" + edges[i].Label
		right := edges[j].From + "\x00" + edges[j].To + "\x00" + edges[j].Label
		return left < right
	})
	return edges
}

func (b *mapBuilder) regionIDs() []string {
	ids := make([]string, 0)
	seen := make(map[string]bool)
	for _, id := range sortedNodeIDs(b.graph) {
		node := b.graph.Nodes[id]
		region := ""
		if node != nil && node.Type == "aws_region" {
			region = strings.TrimPrefix(string(id), regionNodeIDPrefix)
		} else if node != nil {
			region = stringValue(node.Values, "region")
		}
		if region == "" || seen[region] {
			continue
		}
		seen[region] = true
		ids = append(ids, regionNodeIDPrefix+region)
	}
	sort.Strings(ids)
	return ids
}

func (b *mapBuilder) vpcIDs(region string) []graph.ResourceID {
	return b.matchingNodes(func(node *graph.Node) bool {
		return node != nil && node.Type == "aws_vpc" && stringValue(node.Values, "region") == region
	})
}

func (b *mapBuilder) subnetIDs(vpcID graph.ResourceID, region string) []graph.ResourceID {
	vpc := stringValue(b.graph.Nodes[vpcID].Values, "id")
	if vpc == "" {
		vpc = string(vpcID)
	}
	return b.matchingNodes(func(node *graph.Node) bool {
		return node != nil && node.Type == "aws_subnet" && stringValue(node.Values, "region") == region && referencesAny(node, "vpc_id", string(vpcID), vpc)
	})
}

func (b *mapBuilder) nodesForSubnet(subnetID graph.ResourceID) []graph.ResourceID {
	subnet := stringValue(b.graph.Nodes[subnetID].Values, "id")
	if subnet == "" {
		subnet = string(subnetID)
	}
	return b.matchingNodes(func(node *graph.Node) bool {
		return renderableResource(node) && referencesAny(node, "subnet_id", string(subnetID), subnet)
	})
}

func (b *mapBuilder) nodesForVPCWithoutSubnet(vpcID graph.ResourceID, region string) []graph.ResourceID {
	vpc := stringValue(b.graph.Nodes[vpcID].Values, "id")
	if vpc == "" {
		vpc = string(vpcID)
	}
	return b.matchingNodes(func(node *graph.Node) bool {
		return renderableResource(node) &&
			stringValue(node.Values, "region") == region &&
			referencesAny(node, "vpc_id", string(vpcID), vpc) &&
			stringValue(node.Values, "subnet_id") == ""
	})
}

func (b *mapBuilder) nodesForRegionWithoutVPC(region string) []graph.ResourceID {
	return b.matchingNodes(func(node *graph.Node) bool {
		return renderableResource(node) &&
			stringValue(node.Values, "region") == region &&
			stringValue(node.Values, "vpc_id") == "" &&
			stringValue(node.Values, "subnet_id") == ""
	})
}

func (b *mapBuilder) globalNodes() []graph.ResourceID {
	return b.matchingNodes(func(node *graph.Node) bool {
		return renderableResource(node) && stringValue(node.Values, "region") == "" && isGlobalResource(node)
	})
}

func (b *mapBuilder) unplacedNodes() []graph.ResourceID {
	return b.matchingNodes(func(node *graph.Node) bool {
		if node == nil || !renderableResource(node) || b.placed[string(node.ID)] {
			return false
		}
		return true
	})
}

func (b *mapBuilder) matchingNodes(pred func(*graph.Node) bool) []graph.ResourceID {
	ids := make([]graph.ResourceID, 0)
	for _, id := range sortedNodeIDs(b.graph) {
		node := b.graph.Nodes[id]
		if pred(node) {
			ids = append(ids, id)
		}
	}
	return ids
}

func renderableResource(node *graph.Node) bool {
	if node == nil || node.Type == "aws_account" || node.Type == "aws_region" || node.Type == "aws_vpc" || node.Type == "aws_subnet" {
		return false
	}
	return true
}

func isGlobalResource(node *graph.Node) bool {
	if node == nil {
		return false
	}
	return node.ID == graph.InternetNodeID || strings.Contains(node.Type, "iam_") || strings.Contains(node.Type, "cloudfront") || strings.Contains(node.Type, "route53")
}

func referencesAny(node *graph.Node, key string, values ...string) bool {
	actual := stringValue(node.Values, key)
	if actual == "" {
		return false
	}
	for _, value := range values {
		if value != "" && actual == value {
			return true
		}
	}
	return false
}

func labelForNode(node *graph.Node) string {
	if node == nil {
		return ""
	}
	return firstNonEmpty(node.Name, node.Tags["Name"], node.Tags["name"], stringValue(node.Values, "id"), node.Address, string(node.ID))
}

func displayKind(node *graph.Node) string {
	if node == nil || node.Kind == "" || node.Kind == graph.NodeUnknown {
		return "resource"
	}
	return humanize(string(node.Kind))
}

func nodeType(node *graph.Node) string {
	if node == nil {
		return ""
	}
	return node.Type
}

func serviceLabelForNode(node *graph.Node) string {
	if node == nil {
		return "Resource"
	}
	if node.ID == graph.InternetNodeID {
		return "Internet"
	}
	return serviceLabelForType(node.Type)
}

func serviceLabelForType(resourceType string) string {
	normalized := strings.ToLower(resourceType)
	switch {
	case normalized == "":
		return "Resource"
	case strings.Contains(normalized, "api_gateway"):
		return "API Gateway"
	case strings.Contains(normalized, "cloudfront"):
		return "CloudFront"
	case strings.Contains(normalized, "lb"):
		return "Load Balancer"
	case strings.Contains(normalized, "lambda"):
		return "Lambda"
	case strings.Contains(normalized, "ecs_service"):
		return "ECS Service"
	case strings.Contains(normalized, "ecs_task"):
		return "ECS Task"
	case strings.Contains(normalized, "eks"):
		return "EKS"
	case strings.Contains(normalized, "rds") || strings.Contains(normalized, "db_instance"):
		return "RDS"
	case strings.Contains(normalized, "opensearch"):
		return "OpenSearch"
	case strings.Contains(normalized, "elasticache"):
		return "ElastiCache"
	case strings.Contains(normalized, "efs"):
		return "EFS"
	case strings.Contains(normalized, "dynamodb"):
		return "DynamoDB"
	case strings.Contains(normalized, "instance"):
		return "EC2 Instance"
	case strings.Contains(normalized, "s3"):
		return "S3 Bucket"
	case strings.Contains(normalized, "secretsmanager"):
		return "Secrets Manager"
	case strings.Contains(normalized, "kms"):
		return "KMS Key"
	case strings.Contains(normalized, "iam_role"):
		return "IAM Role"
	case strings.Contains(normalized, "iam_policy"):
		return "IAM Policy"
	case strings.Contains(normalized, "security_group"):
		return "Security Group"
	case strings.Contains(normalized, "internet_gateway"):
		return "Internet Gateway"
	case strings.Contains(normalized, "nat_gateway"):
		return "NAT Gateway"
	case strings.Contains(normalized, "subnet"):
		return "Subnet"
	case strings.Contains(normalized, "vpc"):
		return "VPC"
	default:
		return titleCase(humanize(resourceType))
	}
}

func roleForNode(node *graph.Node) string {
	switch {
	case node == nil:
		return "default"
	case node.ID == graph.InternetNodeID:
		return "internet"
	case isPublicNode(node):
		return "public"
	case isSensitiveNode(node):
		return "sensitive"
	case isComputeNode(node):
		return "workload"
	case isIAMNode(node):
		return "principal"
	case isNetworkNode(node):
		return "network"
	default:
		return "default"
	}
}

func iconForNode(node *graph.Node) string {
	if node == nil {
		return "resource"
	}
	switch {
	case node.ID == graph.InternetNodeID:
		return "internet"
	case strings.Contains(node.Type, "api_gateway"):
		return "api"
	case strings.Contains(node.Type, "lb"):
		return "load-balancer"
	case strings.Contains(node.Type, "lambda"):
		return "lambda"
	case strings.Contains(node.Type, "ecs"):
		return "container"
	case strings.Contains(node.Type, "instance"):
		return "compute"
	case strings.Contains(node.Type, "rds") || strings.Contains(node.Type, "db_"):
		return "database"
	case strings.Contains(node.Type, "s3"):
		return "bucket"
	case strings.Contains(node.Type, "secretsmanager"):
		return "secret"
	case strings.Contains(node.Type, "kms"):
		return "key"
	case strings.Contains(node.Type, "iam"):
		return "role"
	case strings.Contains(node.Type, "security_group"):
		return "security-group"
	case strings.Contains(node.Type, "internet_gateway") || strings.Contains(node.Type, "nat_gateway"):
		return "gateway"
	default:
		return "resource"
	}
}

func subnetKind(node *graph.Node) string {
	if isPublicNode(node) {
		return "public-subnet"
	}
	return "private-subnet"
}

func detailsForNode(node *graph.Node) []string {
	if node == nil {
		return nil
	}
	details := []string{}
	for _, key := range []string{"account_id", "region", "availability_zone", "arn", "id", "vpc_id", "subnet_id", "cidr_block"} {
		if value := stringValue(node.Values, key); value != "" {
			details = append(details, humanize(key)+": "+value)
		}
	}
	for _, key := range []string{"public", "endpoint_public_access", "sensitive_data", "encryption_enabled", "public_access_blocked", "deletion_protection"} {
		if value, ok := boolDetail(node.Values, key); ok {
			details = append(details, humanize(key)+": "+fmt.Sprintf("%t", value))
		}
	}
	if reason := stringValue(node.Values, "sensitivity_reason"); reason != "" {
		details = append(details, "sensitivity: "+reason)
	}
	if len(node.Tags) > 0 {
		keys := make([]string, 0, len(node.Tags))
		for key := range node.Tags {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			details = append(details, "tag "+key+": "+node.Tags[key])
		}
	}
	return details
}

func propertiesForNode(node *graph.Node) []mapProperty {
	if node == nil {
		return nil
	}
	properties := make([]mapProperty, 0)
	add := func(group string, key string, value string) {
		if value == "" {
			return
		}
		properties = append(properties, mapProperty{Group: group, Key: humanize(key), Value: value})
	}
	identityKeys := []string{"arn", "id", "account_id", "region", "availability_zone"}
	networkKeys := []string{"vpc_id", "subnet_id", "subnet_ids", "security_group_id", "security_group_ids", "cidr_block", "route_table_id", "internet_gateway_id", "nat_gateway_id", "target_group_arn", "load_balancer_arn"}
	securityKeys := []string{"public", "internet_facing", "endpoint_public_access", "public_access_blocked", "sensitive_data", "sensitivity_reason", "encryption_enabled", "kms_key_id", "deletion_protection", "backup_retention_period", "skip_final_snapshot"}
	runtimeKeys := []string{"state", "status", "engine", "engine_version", "runtime", "handler", "task_role_arn", "execution_role_arn", "role", "service_name", "dns_name", "endpoint", "url", "private_dns_enabled"}
	seen := make(map[string]bool)
	for _, key := range identityKeys {
		if value := propertyValue(node.Values, key); value != "" {
			add("Identity", key, value)
			seen[key] = true
		}
	}
	for _, key := range networkKeys {
		if value := propertyValue(node.Values, key); value != "" {
			add("Network", key, value)
			seen[key] = true
		}
	}
	for _, key := range securityKeys {
		if value := propertyValue(node.Values, key); value != "" {
			add("Security", key, value)
			seen[key] = true
		}
	}
	for _, key := range runtimeKeys {
		if value := propertyValue(node.Values, key); value != "" {
			add("Runtime", key, value)
			seen[key] = true
		}
	}
	extraKeys := make([]string, 0)
	for key := range node.Values {
		if seen[key] || strings.HasPrefix(key, "policy") || strings.Contains(key, "secret") {
			continue
		}
		if value := propertyValue(node.Values, key); value != "" {
			extraKeys = append(extraKeys, key)
		}
	}
	sort.Strings(extraKeys)
	for _, key := range extraKeys {
		if len(properties) >= 48 {
			add("Other", "More fields", "Additional fields omitted from the visual inspector")
			break
		}
		add("Other", key, propertyValue(node.Values, key))
	}
	return properties
}

func tagsForNode(node *graph.Node) []mapProperty {
	if node == nil || len(node.Tags) == 0 {
		return nil
	}
	keys := make([]string, 0, len(node.Tags))
	for key := range node.Tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	tags := make([]mapProperty, 0, len(keys))
	for _, key := range keys {
		tags = append(tags, mapProperty{Key: key, Value: node.Tags[key]})
	}
	return tags
}

func propertyValue(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return fmt.Sprintf("%t", typed)
	case int:
		return fmt.Sprintf("%d", typed)
	case int64:
		return fmt.Sprintf("%d", typed)
	case float64:
		if math.Trunc(typed) == typed {
			return fmt.Sprintf("%.0f", typed)
		}
		return fmt.Sprintf("%.2f", typed)
	case []string:
		return strings.Join(typed, ", ")
	case []any:
		items := make([]string, 0, minInt(len(typed), 8))
		for index, item := range typed {
			if index >= 8 {
				items = append(items, fmt.Sprintf("... %d more", len(typed)-index))
				break
			}
			items = append(items, fmt.Sprint(item))
		}
		return strings.Join(items, ", ")
	case map[string]any:
		return fmt.Sprintf("%d fields", len(typed))
	default:
		return fmt.Sprint(typed)
	}
}

func boolDetail(values map[string]any, key string) (bool, bool) {
	if values == nil {
		return false, false
	}
	value, ok := values[key]
	if !ok {
		return false, false
	}
	typed, ok := value.(bool)
	return typed, ok
}

func metadataForNode(node *graph.Node) map[string]string {
	if node == nil {
		return nil
	}
	out := make(map[string]string)
	for _, key := range []string{"account_id", "region", "availability_zone", "arn", "id", "vpc_id", "subnet_id", "cidr_block"} {
		if value := stringValue(node.Values, key); value != "" {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func humanize(value string) string {
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

func titleCase(value string) string {
	words := strings.Fields(value)
	for index, word := range words {
		if word == "" {
			continue
		}
		words[index] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
	}
	return strings.Join(words, " ")
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func mapStyles() string {
	return `<style>
:root { color-scheme: light; --bg: #f8fafc; --panel: #ffffff; --ink: #0f172a; --muted: #64748b; --line: #cbd5e1; --accent: #2563eb; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
header { padding: 22px 28px 16px; background: #fff; border-bottom: 1px solid var(--line); }
h1 { margin: 0; font-size: 24px; line-height: 1.15; letter-spacing: 0; }
header p { margin: 6px 0 0; color: var(--muted); }
.shell { display: grid; grid-template-columns: minmax(260px, 320px) minmax(0, 1fr); grid-template-areas: "controls canvas"; min-height: calc(100vh - 82px); position: relative; }
body.controls-collapsed .shell { grid-template-columns: 0 minmax(0, 1fr); }
aside { grid-area: controls; background: var(--panel); border-right: 1px solid var(--line); overflow: auto; transition: width .16s ease, opacity .16s ease; }
.controls-panel { padding: 18px; min-width: 260px; }
body.controls-collapsed aside:not(.details) { opacity: 0; pointer-events: none; width: 0; border-right: 0; }
.canvas-wrap { grid-area: canvas; overflow: auto; background: #f8fafc; position: relative; }
.details { position: fixed; top: 82px; right: 0; bottom: 0; z-index: 20; width: min(440px, calc(100vw - 28px)); background: var(--panel); border-left: 1px solid var(--line); box-shadow: -18px 0 32px rgba(15,23,42,.14); padding: 18px 22px; overflow: auto; transform: translateX(102%); transition: transform .18s ease; }
body.drawer-open .details { transform: translateX(0); }
.rail-toggle { position: absolute; z-index: 10; top: 14px; left: 334px; width: auto; min-height: 32px; padding: 0 10px; font-size: 12px; background: #fff; box-shadow: 0 8px 18px rgba(15,23,42,.08); }
body.controls-collapsed .controls-toggle { left: 14px; }
.search { width: 100%; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; font: inherit; }
.buttons { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin-top: 12px; }
.layout-buttons { grid-template-columns: repeat(3, minmax(0, 1fr)); }
button { appearance: none; border: 1px solid var(--line); background: #fff; border-radius: 8px; color: #334155; cursor: pointer; font: inherit; font-weight: 650; min-height: 34px; }
button:hover { border-color: #94a3b8; color: var(--ink); }
.details .icon-button { position: absolute; right: 18px; top: 18px; width: 32px; min-height: 30px; padding: 0; font-size: 18px; line-height: 1; }
.hint { color: var(--muted); font-size: 12px; margin: 10px 0 0; }
.toggle-row { display: flex; align-items: center; gap: 8px; color: #334155; margin-top: 14px; }
.legend { display: grid; gap: 8px; margin-top: 18px; }
.legend label { display: flex; align-items: center; gap: 8px; color: #334155; }
.swatch { width: 14px; height: 14px; border-radius: 4px; border: 1px solid #94a3b8; flex: none; }
.inventory-panel { margin-top: 18px; }
.panel-title { color: #0f172a; font-weight: 750; margin: 0 0 8px; }
.inventory { max-height: 250px; overflow: auto; border: 1px solid var(--line); border-radius: 8px; background: #fff; }
.inventory-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; width: 100%; min-height: auto; padding: 9px 10px; border: 0; border-bottom: 1px solid #e2e8f0; border-radius: 0; text-align: left; font-weight: 500; }
.inventory-row:last-child { border-bottom: 0; }
.inventory-row:hover, .inventory-row.selected { background: #eff6ff; color: #0f172a; }
.inventory-name { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 700; }
.inventory-meta { display: block; color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.inventory-badge { align-self: center; border: 1px solid #cbd5e1; border-radius: 999px; padding: 2px 7px; color: #475569; font-size: 11px; text-transform: capitalize; }
.metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 16px; }
.metrics div { border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #f8fafc; }
.metrics strong { display: block; font-size: 20px; line-height: 1.1; }
.metrics span { color: var(--muted); font-size: 12px; }
svg { min-width: 100%; display: block; cursor: grab; touch-action: none; user-select: none; }
svg.panning { cursor: grabbing; }
.group.account rect { fill: #ffffff; stroke: #94a3b8; stroke-dasharray: 4 3; }
.group.region rect { fill: #eef2ff; stroke: #818cf8; }
.group.vpc rect { fill: #fff7ed; stroke: #f59e0b; }
.group.public-subnet rect { fill: #eff6ff; stroke: #60a5fa; stroke-dasharray: 3 3; }
.group.private-subnet rect { fill: #f0fdf4; stroke: #86efac; stroke-dasharray: 3 3; }
.group.subnet rect, .group.network-resources rect { fill: #f8fafc; stroke: #cbd5e1; }
.group.services rect, .group.global rect { fill: #f8fafc; stroke: #cbd5e1; }
.group-title { font-weight: 750; fill: #0f172a; font-size: 12px; }
.group-subtitle { fill: #64748b; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; }
.group { cursor: move; }
.group.dragging { cursor: grabbing; }
.group.selected > rect { stroke: #111827; stroke-width: 2.8; }
.group.group-member > rect { stroke: #0f766e; stroke-width: 2.2; }
.group-toggle { cursor: pointer; }
.group-toggle rect { fill: rgba(255,255,255,.82); stroke: #cbd5e1; stroke-width: 1; }
.group-toggle text { fill: #334155; font-size: 14px; font-weight: 800; text-anchor: middle; dominant-baseline: central; pointer-events: none; }
.edge { stroke: #94a3b8; stroke-width: 1.8; fill: none; marker-end: url(#arrow); opacity: .86; }
.edge.dim { opacity: .14; }
.edge.connected { stroke: #0f766e; stroke-width: 3.2; opacity: 1; marker-end: url(#arrow-selected); }
.edge.connected.inbound { stroke: #7c3aed; }
.edge.connected.outbound { stroke: #0f766e; }
.edge-label { display: none; fill: #475569; font-size: 10px; font-weight: 650; paint-order: stroke; stroke: #fff; stroke-width: 5px; text-anchor: middle; }
.edge-label.dim { opacity: .16; }
.edge-label.connected { fill: #0f172a; font-size: 11px; opacity: 1; }
body.show-edge-labels .edge-label { display: block; }
.resource { cursor: pointer; }
.resource.dragging { cursor: grabbing; }
.resource.dim { opacity: .24; }
.resource.connected rect { stroke-width: 2.7; }
.resource.connected.inbound rect { stroke: #7c3aed; }
.resource.connected.outbound rect { stroke: #0f766e; }
.resource.group-member rect { stroke: #0f766e; stroke-width: 2.7; }
.resource rect { stroke-width: 2; filter: drop-shadow(0 8px 14px rgba(15,23,42,.08)); }
.resource.public rect { fill: #eff6ff; stroke: #2563eb; }
.resource.workload rect { fill: #ecfeff; stroke: #0891b2; }
.resource.sensitive rect { fill: #fef2f2; stroke: #dc2626; }
.resource.principal rect { fill: #f5f3ff; stroke: #7c3aed; }
.resource.network rect { fill: #f0fdf4; stroke: #16a34a; }
.resource.internet rect { fill: #f0f9ff; stroke: #0284c7; }
.resource.default rect { fill: #ffffff; stroke: #94a3b8; }
.resource.selected rect { stroke: #111827; stroke-width: 3; }
.resource-icon-bg { fill: rgba(255,255,255,.76); stroke: rgba(100,116,139,.35); stroke-width: 1; pointer-events: none; }
.resource-icon { fill: none; stroke: #334155; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; pointer-events: none; }
.resource-icon-fill { fill: #334155; stroke: none; pointer-events: none; }
.resource-title { fill: #0f172a; font-size: 12px; font-weight: 750; pointer-events: none; }
.resource-service { fill: #64748b; font-size: 10px; font-weight: 700; pointer-events: none; }
.hidden { opacity: .08; pointer-events: none; }
.collapsed { opacity: .12; pointer-events: none; }
.minimap { position: sticky; left: calc(100% - 244px); bottom: 18px; z-index: 8; width: 220px; height: 150px; margin: -168px 18px 18px auto; background: rgba(255,255,255,.92); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 12px 24px rgba(15,23,42,.12); overflow: hidden; }
.minimap svg { min-width: 0; width: 100%; height: 100%; cursor: default; }
.mini-group { fill: #e2e8f0; stroke: #94a3b8; stroke-width: .8; }
.mini-node { fill: #2563eb; opacity: .72; }
.minimap-view { fill: rgba(37,99,235,.08); stroke: #2563eb; stroke-width: 1.4; }
.details h2 { margin: 0 0 4px; font-size: 20px; padding-right: 72px; }
.details p { margin: 0 0 12px; color: var(--muted); }
.details-grid { display: grid; grid-template-columns: 1fr; gap: 18px; }
.details dl { display: grid; grid-template-columns: 130px 1fr; gap: 6px 14px; margin: 0; }
.details dt { color: var(--muted); }
.details dd { margin: 0; word-break: break-word; }
.details ul { margin: 8px 0; padding-left: 18px; }
.drawer-hero { margin: -18px -22px 18px; padding: 18px 22px; border-bottom: 1px solid var(--line); background: #f8fafc; }
.drawer-kind { display: inline-flex; align-items: center; border: 1px solid #cbd5e1; border-radius: 999px; padding: 3px 9px; color: #334155; background: #fff; font-size: 12px; font-weight: 700; text-transform: capitalize; }
.drawer-section { border-top: 1px solid #e2e8f0; padding-top: 14px; }
.drawer-section h3 { margin: 0 0 10px; font-size: 15px; }
.property-table { display: grid; gap: 1px; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; background: #e2e8f0; }
.property-row { display: grid; grid-template-columns: minmax(120px, .42fr) minmax(0, 1fr); gap: 12px; padding: 9px 10px; background: #fff; }
.property-key { color: #475569; font-weight: 700; }
.property-value { color: #0f172a; word-break: break-word; white-space: pre-wrap; }
.property-group { margin: 12px 0 6px; color: #334155; font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .06em; }
.connection-list { display: grid; gap: 8px; margin-top: 8px; }
.connection-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 9px 10px; background: #fff; }
.connection-title { font-weight: 750; }
.connection-meta { color: #64748b; font-size: 12px; margin-top: 2px; }
@media (max-width: 980px) { .shell { grid-template-columns: 1fr; grid-template-areas: "canvas"; } .rail-toggle { position: fixed; top: 96px; left: 14px; } aside:not(.details) { position: fixed; top: 82px; left: 0; bottom: 0; z-index: 19; width: min(320px, calc(100vw - 28px)); box-shadow: 18px 0 32px rgba(15,23,42,.12); } body.controls-collapsed aside:not(.details) { transform: translateX(-102%); width: min(320px, calc(100vw - 28px)); } .canvas-wrap { min-height: calc(100vh - 82px); } .details { top: 82px; } }
</style>
`
}

func mapScript() string {
	return `
const data = CHANGEGATE_ARCHITECTURE;
const svg = document.getElementById('map');
const viewport = document.getElementById('viewport');
const canvasWrap = document.querySelector('.canvas-wrap');
const search = document.getElementById('search');
const details = document.getElementById('details');
const controlsToggle = document.getElementById('controls-toggle');
const detailsClose = document.getElementById('details-close');
const edgeLabelToggle = document.getElementById('edge-label-toggle');
const layoutFile = document.getElementById('layout-file');
const inventory = document.getElementById('inventory');
const minimap = document.getElementById('minimap');
const minimapContent = document.getElementById('minimap-content');
const minimapView = document.getElementById('minimap-view');
let transform = { x: 0, y: 0, scale: 1 };
let activePan = null;
let activeDrag = null;
let activeGroupDrag = null;
let selectedNodeId = '';
let selectedGroupId = '';
const collapsedGroups = new Set();
const selectedNodeIds = new Set();
const modifierKeys = { meta: false, ctrl: false, shift: false };
const roleStyles = {
  public: ['#eff6ff', '#2563eb'],
  workload: ['#ecfeff', '#0891b2'],
  sensitive: ['#fef2f2', '#dc2626'],
  principal: ['#f5f3ff', '#7c3aed'],
  network: ['#f0fdf4', '#16a34a'],
  internet: ['#e0f2fe', '#0284c7'],
  default: ['#ffffff', '#94a3b8']
};
const nodesById = new Map(data.nodes.map((node) => [node.id, node]));
const groupsById = new Map(data.groups.map((group) => [group.id, group]));
const positions = new Map(data.nodes.map((node) => [node.id, { x: node.x, y: node.y, width: node.width, height: node.height }]));
const groupPositions = new Map(data.groups.map((group) => [group.id, { x: group.x, y: group.y, width: group.width, height: group.height }]));
const nodeElements = new Map();
const groupElements = new Map();
const edgeElements = [];
const edgeLabelElements = [];
const edgeRecords = [];

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}
function roleLabel(value) { return String(value || 'default').replaceAll('_', ' '); }
function groupLabel(value) { return String(value || 'section').replaceAll('_', ' ').replaceAll('-', ' '); }
function serviceLine(node) {
  return (node.service || node.type || 'Resource') + ' / ' + roleLabel(node.role || 'resource');
}
function cardServiceLabel(node) {
  return node.service || node.type || 'Resource';
}
function truncateText(value, maxChars) {
  const text = String(value || '');
  if (text.length <= maxChars) return text;
  return text.slice(0, Math.max(0, maxChars - 1)).replace(/[ /.-]+$/, '') + '…';
}
function additiveSelectionActive(event) {
  return Boolean(
    event?.metaKey ||
    event?.ctrlKey ||
    event?.shiftKey ||
    (event?.getModifierState && (event.getModifierState('Meta') || event.getModifierState('Control') || event.getModifierState('Shift'))) ||
    modifierKeys.meta ||
    modifierKeys.ctrl ||
    modifierKeys.shift
  );
}
function draw() {
  viewport.innerHTML = '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#94a3b8"/></marker><marker id="arrow-selected" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#0f766e"/></marker></defs>';
  nodeElements.clear();
  groupElements.clear();
  edgeElements.length = 0;
  edgeLabelElements.length = 0;
  edgeRecords.length = 0;
  data.groups.forEach(drawGroup);
  data.edges.forEach(drawEdge);
  data.nodes.forEach(drawNode);
  buildLegend();
  buildInventory();
  drawMiniMap();
  document.getElementById('metric-nodes').textContent = data.nodes.length;
  document.getElementById('metric-edges').textContent = data.edges.length;
  document.getElementById('metric-public').textContent = (data.summary.public_resources || []).length;
  document.getElementById('metric-sensitive').textContent = (data.summary.sensitive_assets || []).length;
  applyFilters();
}
function drawGroup(group) {
  const element = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  element.setAttribute('class', 'group ' + escapeHTML(group.kind || 'services'));
  element.setAttribute('data-id', group.id);
  const groupPosition = groupPositions.get(group.id) || { x: group.x, y: group.y, width: group.width, height: group.height };
  group.x = groupPosition.x;
  group.y = groupPosition.y;
  group.width = groupPosition.width;
  group.height = groupPosition.height;
  const toggleX = groupPosition.x + 12;
  element.innerHTML =
    '<rect x="' + groupPosition.x + '" y="' + groupPosition.y + '" width="' + groupPosition.width + '" height="' + groupPosition.height + '" rx="8"></rect>' +
    '<text class="group-title" x="' + (groupPosition.x + 42) + '" y="' + (groupPosition.y + 22) + '">' + escapeHTML(group.label) + '</text>' +
    '<text class="group-subtitle" x="' + (groupPosition.x + 42) + '" y="' + (groupPosition.y + 38) + '">' + escapeHTML(groupLabel(group.kind)) + '</text>' +
    '<g class="group-toggle" data-toggle-group="' + escapeHTML(group.id) + '"><rect x="' + toggleX + '" y="' + (groupPosition.y + 9) + '" width="20" height="20" rx="5"></rect><text x="' + (toggleX + 10) + '" y="' + (groupPosition.y + 20) + '">' + (collapsedGroups.has(group.id) ? '+' : '−') + '</text></g>';
  element.addEventListener('pointerdown', (event) => startGroupDrag(event, group.id, element));
  element.addEventListener('click', (event) => { event.stopPropagation(); if (!element.dataset.dragged) selectGroup(group.id); delete element.dataset.dragged; });
  const toggle = element.querySelector('[data-toggle-group]');
  if (toggle) {
    toggle.addEventListener('pointerdown', (event) => event.stopPropagation());
    toggle.addEventListener('click', (event) => { event.stopPropagation(); toggleGroup(group.id); });
  }
  groupElements.set(group.id, element);
  viewport.appendChild(element);
}
function drawNode(node) {
  const element = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  element.setAttribute('class', 'resource ' + (node.role || 'default'));
  element.setAttribute('data-id', node.id);
  element.setAttribute('data-role', node.role || 'default');
  element.setAttribute('aria-label', (node.label || node.id) + ' - ' + serviceLine(node));
  const position = positions.get(node.id) || { x: node.x, y: node.y, width: node.width, height: node.height };
  node.x = position.x;
  node.y = position.y;
  element.setAttribute('transform', 'translate(' + position.x + ' ' + position.y + ')');
  element.innerHTML =
    '<title>' + escapeHTML((node.label || node.id) + ' - ' + serviceLine(node)) + '</title>' +
    '<rect width="' + node.width + '" height="' + node.height + '" rx="7"></rect>' +
    iconMarkup(node) +
    textLines(node.label || node.id, 'resource-title', 44, 22, 17, 2) +
    '<text class="resource-service" x="44" y="52">' + escapeHTML(truncateText(cardServiceLabel(node), 20)) + '</text>';
  element.addEventListener('pointerdown', (event) => startNodeDrag(event, node.id, element));
  element.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    const additive = additiveSelectionActive(event) || element.dataset.additiveClick === 'true';
    if (!element.dataset.dragged && element.dataset.selectionHandled !== 'true') {
      if (!additive && selectedNodeIds.size > 1 && selectedNodeIds.has(node.id)) {
        selectedNodeId = node.id;
        applySelectionHighlight();
      } else {
        selectNode(node.id, additive);
      }
    }
    delete element.dataset.additiveClick;
    delete element.dataset.selectionHandled;
    delete element.dataset.dragged;
  });
  nodeElements.set(node.id, element);
  viewport.appendChild(element);
}
function iconMarkup(node) {
  return '<g transform="translate(12 17)">' +
    '<rect class="resource-icon-bg" x="-4" y="-4" width="24" height="24" rx="6"></rect>' +
    iconPath(node.icon || node.role || 'resource') +
    '</g>';
}
function iconPath(icon) {
  switch (icon) {
    case 'internet': return '<path class="resource-icon" d="M2 11c1-4 8-4 9 0h1a4 4 0 0 1 0 8H4a4 4 0 0 1-2-8z" transform="scale(.78) translate(0 -2)"></path>';
    case 'load-balancer': return '<circle class="resource-icon" cx="8" cy="8" r="3"></circle><path class="resource-icon" d="M8 1v4M8 11v4M1 8h4M11 8h4"></path>';
    case 'api': return '<path class="resource-icon" d="M2 4h12v8H2zM5 7h6M5 10h4"></path>';
    case 'lambda': return '<path class="resource-icon" d="M3 13l4-10h3l4 10M6 8h5"></path>';
    case 'container': return '<path class="resource-icon" d="M2 4l6-3 6 3v8l-6 3-6-3zM2 4l6 3 6-3M8 7v8"></path>';
    case 'compute': return '<rect class="resource-icon" x="3" y="3" width="10" height="10" rx="1"></rect><path class="resource-icon" d="M1 6h2M1 10h2M13 6h2M13 10h2M6 1v2M10 1v2M6 13v2M10 13v2"></path>';
    case 'database': return '<ellipse class="resource-icon" cx="8" cy="4" rx="5" ry="2.5"></ellipse><path class="resource-icon" d="M3 4v8c0 1.4 10 1.4 10 0V4M3 8c0 1.4 10 1.4 10 0"></path>';
    case 'bucket': return '<path class="resource-icon" d="M3 4h10l-1 10H4zM3 4l2-2h6l2 2"></path>';
    case 'secret': return '<circle class="resource-icon" cx="6" cy="6" r="3"></circle><path class="resource-icon" d="M8.5 8.5L14 14M11 11l2-2M12.5 12.5l2-2"></path>';
    case 'key': return '<circle class="resource-icon" cx="5" cy="8" r="3"></circle><path class="resource-icon" d="M8 8h7M12 8v3M14 8v2"></path>';
    case 'role': return '<circle class="resource-icon" cx="8" cy="5" r="3"></circle><path class="resource-icon" d="M3 14c1-4 9-4 10 0"></path>';
    case 'security-group': return '<path class="resource-icon" d="M8 1l6 3v4c0 4-3 6-6 7-3-1-6-3-6-7V4z"></path><path class="resource-icon" d="M5 8l2 2 4-4"></path>';
    case 'gateway': return '<path class="resource-icon" d="M2 8h12M8 2v12M4 4l-2 4 2 4M12 4l2 4-2 4"></path>';
    default: return '<rect class="resource-icon" x="3" y="3" width="10" height="10" rx="2"></rect>';
  }
}
function textLines(value, cls, x, y, maxChars, maxLines) {
  const words = String(value || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let current = '';
  words.forEach((word) => {
    if (!current) { current = word; return; }
    if ((current + ' ' + word).length > maxChars && lines.length < maxLines - 1) {
      lines.push(current); current = word;
    } else {
      current += ' ' + word;
    }
  });
  if (current) lines.push(current);
  const trimmed = lines.slice(0, maxLines);
  if (trimmed.join(' ') !== words.join(' ') && trimmed.length) trimmed[trimmed.length - 1] = trimmed[trimmed.length - 1].replace(/[. ]+$/, '') + '...';
  return trimmed.map((line, index) => '<text class="' + cls + '" x="' + x + '" y="' + (y + index * 14) + '">' + escapeHTML(line) + '</text>').join('');
}
function drawEdge(edge) {
  const from = nodesById.get(edge.from);
  const to = nodesById.get(edge.to);
  if (!from || !to) return;
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('class', 'edge');
  path.setAttribute('data-from', edge.from);
  path.setAttribute('data-to', edge.to);
  viewport.appendChild(path);
  edgeElements.push(path);
  let label = null;
  if (edge.label) {
    label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('class', 'edge-label');
    label.setAttribute('data-from', edge.from);
    label.setAttribute('data-to', edge.to);
    label.textContent = edge.label;
    viewport.appendChild(label);
  }
  edgeLabelElements.push(label);
  edgeRecords.push({ edge, path, label });
  updateEdgeGeometry(path, label);
}
function buildLegend() {
  const legend = document.getElementById('legend');
  const counts = new Map();
  data.nodes.forEach((node) => counts.set(node.role || 'default', (counts.get(node.role || 'default') || 0) + 1));
  legend.innerHTML = Array.from(counts.keys()).sort().map((role) => {
    const style = roleStyles[role] || roleStyles.default;
    return '<label><input type="checkbox" data-role-filter="' + escapeHTML(role) + '" checked><span class="swatch" style="background:' + style[0] + ';border-color:' + style[1] + '"></span>' + escapeHTML(roleLabel(role)) + ' (' + counts.get(role) + ')</label>';
  }).join('');
  legend.querySelectorAll('input').forEach((input) => input.addEventListener('change', applyFilters));
}
function buildInventory() {
  const sorted = [...data.nodes].sort((a, b) => String(a.label || a.id).localeCompare(String(b.label || b.id)));
  inventory.innerHTML = sorted.map((node) =>
    '<button type="button" class="inventory-row" data-inventory-id="' + escapeHTML(node.id) + '">' +
      '<span><span class="inventory-name">' + escapeHTML(node.label || node.id) + '</span><span class="inventory-meta">' + escapeHTML((node.service || node.type || 'Resource') + (node.type ? ' / ' + node.type : '')) + '</span></span>' +
      '<span class="inventory-badge">' + escapeHTML(node.role || 'resource') + '</span>' +
    '</button>'
  ).join('');
  inventory.querySelectorAll('[data-inventory-id]').forEach((row) => {
    row.addEventListener('click', () => {
      const id = row.dataset.inventoryId;
      selectNode(id);
      focusNode(id);
    });
  });
}
function activeRoles() {
  return new Set(Array.from(document.querySelectorAll('[data-role-filter]')).filter((input) => input.checked).map((input) => input.dataset.roleFilter));
}
function applyFilters() {
  const query = search.value.trim().toLowerCase();
  const roles = activeRoles();
  const visible = new Set();
  document.querySelectorAll('.resource').forEach((element) => {
    const node = nodesById.get(element.dataset.id);
    const propHaystack = [...(node.properties || []), ...(node.tags || [])].map((item) => item.key + ' ' + item.value);
    const show = isVisibleByCollapse(node.id) && roles.has(node.role || 'default') && matchesQuery(node, propHaystack, query);
    element.classList.toggle('hidden', !show);
    if (show) visible.add(node.id);
  });
  inventory.querySelectorAll('[data-inventory-id]').forEach((row) => {
    const node = nodesById.get(row.dataset.inventoryId);
    const propHaystack = [...(node.properties || []), ...(node.tags || [])].map((item) => item.key + ' ' + item.value);
    const show = isVisibleByCollapse(node.id) && roles.has(node.role || 'default') && matchesQuery(node, propHaystack, query);
    row.hidden = !show;
    row.classList.toggle('selected', row.dataset.inventoryId === selectedNodeId);
  });
  document.querySelectorAll('.edge,.edge-label').forEach((element) => {
    const show = visible.has(element.dataset.from) && visible.has(element.dataset.to);
    element.classList.toggle('hidden', !show);
  });
  applySelectionHighlight();
  updateMiniMapViewport();
}
function matchesQuery(node, extra, query) {
  const haystack = [node.id, node.label, node.kind, node.type, node.service, node.role, ...(node.details || []), ...extra].join(' ').toLowerCase();
  return !query || haystack.includes(query);
}
function isVisibleByCollapse(id) {
  const node = nodesById.get(id);
  let parent = node ? node.parent : '';
  while (parent) {
    if (collapsedGroups.has(parent)) return false;
    const group = groupsById.get(parent);
    parent = group ? group.parent : '';
  }
  return true;
}
function toggleGroup(id) {
  if (collapsedGroups.has(id)) collapsedGroups.delete(id); else collapsedGroups.add(id);
  draw();
}
function expandAllGroups() {
  collapsedGroups.clear();
  draw();
}
function selectNode(id, additive = false) {
  selectedGroupId = '';
  if (additive) {
    if (selectedNodeIds.has(id)) selectedNodeIds.delete(id); else selectedNodeIds.add(id);
    if (!selectedNodeIds.size) selectedNodeIds.add(id);
  } else {
    selectedNodeIds.clear();
    selectedNodeIds.add(id);
  }
  selectedNodeId = id;
  const node = nodesById.get(id);
  const connected = data.edges.flatMap((edge) => edge.from === id ? [{direction:'outbound', phrase:'to', other:edge.to, label:edge.label, confidence:edge.confidence, details: edge.details || []}] : edge.to === id ? [{direction:'inbound', phrase:'from', other:edge.from, label:edge.label, confidence:edge.confidence, details: edge.details || []}] : []);
  details.innerHTML =
    '<button id="details-close-active" class="icon-button" type="button" aria-label="Close details">&times;</button>' +
    '<div class="drawer-hero"><span class="drawer-kind">' + escapeHTML(node.service || 'Resource') + '</span> <span class="drawer-kind">' + escapeHTML(roleLabel(node.role || 'resource')) + '</span><h2>' + escapeHTML(node.label || node.id) + '</h2><p>' + escapeHTML(node.id) + '</p></div>' +
    '<div class="details-grid"><div class="drawer-section"><h3>Overview</h3><dl>' +
    row('Service', node.service || 'Resource') + row('Role', roleLabel(node.role || 'resource')) + row('Kind', node.kind || 'resource') + row('Type', node.type || 'n/a') + row('Container', parentLabel(node.parent)) + row('Connections', String(connected.length)) +
    '</dl></div>' +
    '<div class="drawer-section"><h3>Connections</h3>' + connectionList(connected) + '</div>' +
    '<div class="drawer-section"><h3>Properties</h3>' + propertySections(node.properties || []) + '</div>' +
    '<div class="drawer-section"><h3>Tags</h3>' + propertyTable(node.tags || []) + '</div>' +
    '<div class="drawer-section"><h3>Notes</h3><ul>' + ((node.details || []).map((item) => '<li>' + escapeHTML(item) + '</li>').join('') || '<li>No additional metadata.</li>') + '</ul></div></div>';
  openDrawer();
  applySelectionHighlight();
}
function selectGroup(id) {
  selectedNodeId = '';
  selectedGroupId = id;
  selectedNodeIds.clear();
  const group = groupsById.get(id);
  const contained = group.children || [];
  details.innerHTML =
    '<button id="details-close-active" class="icon-button" type="button" aria-label="Close details">&times;</button>' +
    '<div class="drawer-hero"><span class="drawer-kind">' + escapeHTML(groupLabel(group.kind || 'container')) + '</span><h2>' + escapeHTML(group.label) + '</h2><p>' + escapeHTML(group.id) + '</p></div>' +
    '<div class="details-grid"><div class="drawer-section"><h3>Overview</h3><dl>' + row('Kind', groupLabel(group.kind)) + row('Contents', String(contained.length)) + row('Parent', parentLabel(group.parent)) + row('State', collapsedGroups.has(id) ? 'collapsed' : 'expanded') + '</dl></div>' +
    '<div class="drawer-section"><h3>Contained items</h3><ul>' + (contained.map((child) => '<li>' + escapeHTML(childLabel(child)) + '</li>').join('') || '<li>No resources in this container.</li>') + '</ul></div></div>';
  openDrawer();
  applySelectionHighlight();
}
function childLabel(id) {
  const node = nodesById.get(id);
  if (node) return (node.label || node.id) + ' (' + (node.service || node.type || node.role || 'resource') + ')';
  const group = groupsById.get(id);
  return group ? group.label + ' (' + groupLabel(group.kind) + ')' : id;
}
function parentLabel(id) {
  if (!id) return 'n/a';
  const group = groupsById.get(id);
  return group ? group.label : id;
}
function row(label, value) { return '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value) + '</dd>'; }
function propertySections(properties) {
  if (!properties.length) return '<p>No structured properties in this view.</p>';
  const groups = new Map();
  properties.forEach((item) => {
    const group = item.group || 'Properties';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(item);
  });
  return Array.from(groups.entries()).map(([group, rows]) => '<div class="property-group">' + escapeHTML(group) + '</div>' + propertyTable(rows)).join('');
}
function propertyTable(properties) {
  if (!properties.length) return '<p>No values available.</p>';
  return '<div class="property-table">' + properties.map((item) => '<div class="property-row"><div class="property-key">' + escapeHTML(item.key) + '</div><div class="property-value">' + escapeHTML(item.value) + '</div></div>').join('') + '</div>';
}
function connectionList(connected) {
  if (!connected.length) return '<p>No connected relationships in this view.</p>';
  return '<div class="connection-list">' + connected.map((edge) => {
    const other = nodesById.get(edge.other);
    return '<div class="connection-card ' + escapeHTML(edge.direction) + '"><div class="connection-title">' + escapeHTML(edge.direction === 'outbound' ? 'Outbound to' : 'Inbound from') + ' ' + escapeHTML(other ? (other.label || other.id) : edge.other) + '</div><div class="connection-meta">' + escapeHTML(other ? (other.service || other.type || 'Resource') + ' / ' : '') + escapeHTML(edge.label || 'relationship') + (edge.confidence ? ' / ' + escapeHTML(edge.confidence) + ' confidence' : '') + '</div></div>';
  }).join('') + '</div>';
}
function updateViewport() {
  viewport.setAttribute('transform', 'translate(' + transform.x + ' ' + transform.y + ') scale(' + transform.scale + ')');
  updateMiniMapViewport();
}
function zoomBy(factor) { transform.scale = Math.min(2.4, Math.max(0.35, transform.scale * factor)); updateViewport(); }
function resetView() { transform = { x: 0, y: 0, scale: 1 }; updateViewport(); }
function focusNode(id) {
  const position = positions.get(id);
  if (!position) return;
  const drawerOpen = document.body.classList.contains('drawer-open');
  const obscuredRight = drawerOpen ? Math.min(details.offsetWidth || 0, canvasWrap.clientWidth || 0) : 0;
  const visibleWidth = Math.max(320, (canvasWrap.clientWidth || 900) - obscuredRight);
  const visibleHeight = Math.max(260, canvasWrap.clientHeight || 700);
  const viewBox = svg.viewBox && svg.viewBox.baseVal ? svg.viewBox.baseVal : { width: data.width || visibleWidth, height: data.height || visibleHeight };
  const svgRect = svg.getBoundingClientRect();
  const cssScaleX = svgRect.width && viewBox.width ? svgRect.width / viewBox.width : 1;
  const cssScaleY = svgRect.height && viewBox.height ? svgRect.height / viewBox.height : 1;
  const visibleWidthInSVG = visibleWidth / cssScaleX;
  const visibleHeightInSVG = visibleHeight / cssScaleY;
  transform.x = visibleWidthInSVG * 0.35 - (position.x + position.width / 2) * transform.scale;
  transform.y = visibleHeightInSVG / 2 - (position.y + position.height / 2) * transform.scale;
  updateViewport();
}
function capturePointer(element, pointerId) { try { element.setPointerCapture(pointerId); } catch (_error) {} }
function releasePointer(element, pointerId) { if (element.hasPointerCapture && element.hasPointerCapture(pointerId)) element.releasePointerCapture(pointerId); }
function openDrawer() {
  document.body.classList.add('drawer-open');
  details.setAttribute('aria-hidden', 'false');
  const close = document.getElementById('details-close-active');
  if (close) close.addEventListener('click', closeDrawer);
}
function closeDrawer() {
  document.body.classList.remove('drawer-open');
  details.setAttribute('aria-hidden', 'true');
  selectedNodeId = '';
  selectedGroupId = '';
  selectedNodeIds.clear();
  document.querySelectorAll('.resource').forEach((node) => node.classList.remove('selected'));
  clearSelectionHighlight();
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
function startNodeDrag(event, id, element) {
  const additive = additiveSelectionActive(event);
  if (additive) event.preventDefault();
  element.dataset.additiveClick = additive ? 'true' : 'false';
  if (additive && !selectedNodeIds.has(id)) {
    selectNode(id, true);
    element.dataset.selectionHandled = 'true';
  }
  const start = graphPoint(event);
  const current = positions.get(id);
  const nodeIds = selectedNodeIds.has(id) ? [...selectedNodeIds] : [id];
  const origins = new Map(nodeIds.map((nodeId) => [nodeId, positions.get(nodeId)]).filter((entry) => entry[1]).map(([nodeId, position]) => [nodeId, {...position}]));
  activeDrag = { id, element, start, dx: start.x - current.x, dy: start.y - current.y, nodeIds, origins, moved: false };
  element.classList.add('dragging');
  capturePointer(element, event.pointerId);
  event.stopPropagation();
}
function startGroupDrag(event, id, element) {
  if (event.target.closest && event.target.closest('.group-toggle')) return;
  const start = graphPoint(event);
  const groupIds = descendantGroupIDs(id);
  const nodeIds = descendantNodeIDs(id);
  const groupOrigins = new Map(groupIds.map((groupId) => [groupId, {...groupPositions.get(groupId)}]));
  const nodeOrigins = new Map(nodeIds.map((nodeId) => [nodeId, {...positions.get(nodeId)}]));
  const ancestorIds = ancestorGroupIDs(id);
  const ancestorOrigins = new Map(ancestorIds.map((groupId) => [groupId, {...groupPositions.get(groupId)}]));
  activeGroupDrag = { id, element, start, groupIds, nodeIds, groupOrigins, nodeOrigins, ancestorIds, ancestorOrigins, moved: false };
  element.classList.add('dragging');
  capturePointer(element, event.pointerId);
  event.stopPropagation();
}
function ancestorGroupIDs(id) {
  const out = [];
  let parent = groupsById.get(id)?.parent || '';
  while (parent) {
    if (!groupsById.has(parent)) break;
    out.push(parent);
    parent = groupsById.get(parent).parent || '';
  }
  return out;
}
function descendantGroupIDs(id) {
  const out = [];
  const seen = new Set();
  const visit = (groupId) => {
    if (seen.has(groupId) || !groupsById.has(groupId)) return;
    seen.add(groupId);
    out.push(groupId);
    (groupsById.get(groupId).children || []).forEach((child) => {
      if (groupsById.has(child)) visit(child);
    });
  };
  visit(id);
  return out;
}
function descendantNodeIDs(id) {
  const out = [];
  const seen = new Set();
  const visit = (groupId) => {
    const group = groupsById.get(groupId);
    if (!group) return;
    (group.children || []).forEach((child) => {
      if (nodesById.has(child) && !seen.has(child)) {
        seen.add(child);
        out.push(child);
      }
      if (groupsById.has(child)) visit(child);
    });
  };
  visit(id);
  return out;
}
function setNodePosition(id, x, y) {
  const position = positions.get(id);
  if (!position) return;
  position.x = x;
  position.y = y;
  const node = nodesById.get(id);
  if (node) {
    node.x = x;
    node.y = y;
  }
  const element = nodeElements.get(id);
  if (element) element.setAttribute('transform', 'translate(' + x.toFixed(1) + ' ' + y.toFixed(1) + ')');
  updateConnectedEdges(id);
  drawMiniMap();
  applySelectionHighlight();
}
function moveActiveNodeDrag(point) {
  const dx = point.x - activeDrag.start.x;
  const dy = point.y - activeDrag.start.y;
  if (Math.abs(dx) > 1 || Math.abs(dy) > 1) {
    activeDrag.moved = true;
    activeDrag.element.dataset.dragged = 'true';
  }
  activeDrag.nodeIds.forEach((nodeId) => {
    const origin = activeDrag.origins.get(nodeId);
    if (!origin) return;
    const position = positions.get(nodeId);
    if (!position) return;
    position.x = origin.x + dx;
    position.y = origin.y + dy;
    const node = nodesById.get(nodeId);
    if (node) {
      node.x = position.x;
      node.y = position.y;
    }
    const element = nodeElements.get(nodeId);
    if (element) element.setAttribute('transform', 'translate(' + position.x.toFixed(1) + ' ' + position.y.toFixed(1) + ')');
  });
  updateAllEdges();
  drawMiniMap();
  applySelectionHighlight();
}
function setGroupPosition(id, x, y) {
  const position = groupPositions.get(id);
  if (!position) return;
  const dx = x - position.x;
  const dy = y - position.y;
  position.x = x;
  position.y = y;
  const group = groupsById.get(id);
  if (group) {
    group.x = x;
    group.y = y;
  }
  const element = groupElements.get(id);
  if (element) element.setAttribute('transform', 'translate(' + dx.toFixed(1) + ' ' + dy.toFixed(1) + ')');
}
function moveActiveGroupDrag(point) {
  const dx = point.x - activeGroupDrag.start.x;
  const dy = point.y - activeGroupDrag.start.y;
  if (Math.abs(dx) > 1 || Math.abs(dy) > 1) {
    activeGroupDrag.moved = true;
    activeGroupDrag.element.dataset.dragged = 'true';
  }
  activeGroupDrag.groupIds.forEach((groupId) => {
    const origin = activeGroupDrag.groupOrigins.get(groupId);
    const position = groupPositions.get(groupId);
    if (!origin || !position) return;
    position.x = origin.x + dx;
    position.y = origin.y + dy;
    const group = groupsById.get(groupId);
    if (group) {
      group.x = position.x;
      group.y = position.y;
    }
    const element = groupElements.get(groupId);
    if (element) element.setAttribute('transform', 'translate(' + dx.toFixed(1) + ' ' + dy.toFixed(1) + ')');
  });
  activeGroupDrag.nodeIds.forEach((nodeId) => {
    const origin = activeGroupDrag.nodeOrigins.get(nodeId);
    const position = positions.get(nodeId);
    if (!origin || !position) return;
    position.x = origin.x + dx;
    position.y = origin.y + dy;
    const node = nodesById.get(nodeId);
    if (node) {
      node.x = position.x;
      node.y = position.y;
    }
    const element = nodeElements.get(nodeId);
    if (element) element.setAttribute('transform', 'translate(' + position.x.toFixed(1) + ' ' + position.y.toFixed(1) + ')');
  });
  expandAncestorsForActiveGroup();
  updateAllEdges();
  drawMiniMap();
  applySelectionHighlight();
}
function expandAncestorsForActiveGroup() {
  if (!activeGroupDrag || !activeGroupDrag.moved) return;
  activeGroupDrag.ancestorIds.forEach((groupId) => {
    const origin = activeGroupDrag.ancestorOrigins.get(groupId);
    const position = groupPositions.get(groupId);
    if (!origin || !position) return;
    position.x = origin.x;
    position.y = origin.y;
    position.width = origin.width;
    position.height = origin.height;
    const children = containedBounds(groupId);
    if (!children) return;
    const padding = 28;
    const right = Math.max(origin.x + origin.width, children.right + padding);
    const bottom = Math.max(origin.y + origin.height, children.bottom + padding);
    const left = Math.min(origin.x, children.left - padding);
    const top = Math.min(origin.y, children.top - padding);
    position.x = left;
    position.y = top;
    position.width = right - left;
    position.height = bottom - top;
    const group = groupsById.get(groupId);
    if (group) {
      group.x = position.x;
      group.y = position.y;
      group.width = position.width;
      group.height = position.height;
    }
    updateGroupElementGeometry(groupId);
  });
}
function containedBounds(groupId) {
  const group = groupsById.get(groupId);
  if (!group) return null;
  let bounds = null;
  const include = (rect) => {
    if (!rect) return;
    if (!bounds) {
      bounds = { left: rect.x, top: rect.y, right: rect.x + rect.width, bottom: rect.y + rect.height };
      return;
    }
    bounds.left = Math.min(bounds.left, rect.x);
    bounds.top = Math.min(bounds.top, rect.y);
    bounds.right = Math.max(bounds.right, rect.x + rect.width);
    bounds.bottom = Math.max(bounds.bottom, rect.y + rect.height);
  };
  (group.children || []).forEach((child) => {
    if (groupPositions.has(child)) include(groupPositions.get(child));
    if (positions.has(child)) include(positions.get(child));
  });
  return bounds;
}
function updateGroupElementGeometry(groupId) {
  const element = groupElements.get(groupId);
  const position = groupPositions.get(groupId);
  if (!element || !position) return;
  const rect = element.querySelector('rect');
  const title = element.querySelector('.group-title');
  const subtitle = element.querySelector('.group-subtitle');
  const toggle = element.querySelector('.group-toggle');
  if (rect) {
    rect.setAttribute('x', position.x.toFixed(1));
    rect.setAttribute('y', position.y.toFixed(1));
    rect.setAttribute('width', position.width.toFixed(1));
    rect.setAttribute('height', position.height.toFixed(1));
  }
  if (title) {
    title.setAttribute('x', (position.x + 42).toFixed(1));
    title.setAttribute('y', (position.y + 22).toFixed(1));
  }
  if (subtitle) {
    subtitle.setAttribute('x', (position.x + 42).toFixed(1));
    subtitle.setAttribute('y', (position.y + 38).toFixed(1));
  }
  if (toggle) {
    const toggleRect = toggle.querySelector('rect');
    const toggleText = toggle.querySelector('text');
    const toggleX = position.x + 12;
    if (toggleRect) {
      toggleRect.setAttribute('x', toggleX.toFixed(1));
      toggleRect.setAttribute('y', (position.y + 9).toFixed(1));
    }
    if (toggleText) {
      toggleText.setAttribute('x', (toggleX + 10).toFixed(1));
      toggleText.setAttribute('y', (position.y + 20).toFixed(1));
    }
  }
}
function updateConnectedEdges(id) {
  edgeElements.forEach((edge, index) => {
    if (edge.dataset.from === id || edge.dataset.to === id) updateEdgeGeometry(edge, edgeLabelElements[index]);
  });
}
function updateAllEdges() {
  edgeElements.forEach((edge, index) => updateEdgeGeometry(edge, edgeLabelElements[index]));
}
function updateEdgeGeometry(edge, label) {
  const from = positions.get(edge.dataset.from);
  const to = positions.get(edge.dataset.to);
  if (!from || !to) return;
  const x1 = from.x + from.width / 2;
  const y1 = from.y + from.height / 2;
  const x2 = to.x + to.width / 2;
  const y2 = to.y + to.height / 2;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const curve = Math.max(36, Math.min(160, Math.hypot(dx, dy) * .28));
  const cx1 = x1 + Math.sign(dx || 1) * curve;
  const cy1 = y1 + dy * .12;
  const cx2 = x2 - Math.sign(dx || 1) * curve;
  const cy2 = y2 - dy * .12;
  edge.setAttribute('d', 'M ' + x1.toFixed(1) + ' ' + y1.toFixed(1) + ' C ' + cx1.toFixed(1) + ' ' + cy1.toFixed(1) + ', ' + cx2.toFixed(1) + ' ' + cy2.toFixed(1) + ', ' + x2.toFixed(1) + ' ' + y2.toFixed(1));
  if (label) {
    label.setAttribute('x', ((x1 + x2) / 2).toFixed(1));
    label.setAttribute('y', ((y1 + y2) / 2 - 6).toFixed(1));
  }
}
function applySelectionHighlight() {
  if (!selectedNodeId && !selectedGroupId && !selectedNodeIds.size) {
    clearSelectionHighlight();
    return;
  }
  const selectedNodes = new Set(selectedNodeIds);
  const related = new Set(selectedNodes);
  const groupNodes = selectedGroupId ? new Set(descendantNodeIDs(selectedGroupId)) : new Set();
  const groupIds = selectedGroupId ? new Set(descendantGroupIDs(selectedGroupId)) : new Set();
  if (selectedGroupId) {
    groupNodes.forEach((id) => related.add(id));
    edgeRecords.forEach(({edge}) => {
      if (groupNodes.has(edge.from) || groupNodes.has(edge.to)) {
        related.add(edge.from);
        related.add(edge.to);
      }
    });
  }
  if (selectedNodeId) {
    related.add(selectedNodeId);
    edgeRecords.forEach(({edge}) => {
      if (edge.from === selectedNodeId) related.add(edge.to);
      if (edge.to === selectedNodeId) related.add(edge.from);
    });
  }
  groupElements.forEach((element, id) => {
    element.classList.toggle('selected', id === selectedGroupId);
    element.classList.toggle('group-member', selectedGroupId && id !== selectedGroupId && groupIds.has(id));
  });
  nodeElements.forEach((element, id) => {
    const inGroup = groupNodes.has(id);
    element.classList.toggle('dim', !related.has(id));
    element.classList.toggle('group-member', inGroup);
    element.classList.toggle('connected', !inGroup && related.has(id) && id !== selectedNodeId && !selectedNodes.has(id));
    element.classList.toggle('outbound', selectedNodeId && data.edges.some((edge) => edge.from === selectedNodeId && edge.to === id));
    element.classList.toggle('inbound', selectedNodeId && data.edges.some((edge) => edge.to === selectedNodeId && edge.from === id));
    element.classList.toggle('selected', selectedNodes.has(id));
  });
  edgeRecords.forEach(({edge, path, label}) => {
    const selectedEndpoint = selectedNodeId && (edge.from === selectedNodeId || edge.to === selectedNodeId);
    const groupConnected = selectedGroupId && (groupNodes.has(edge.from) || groupNodes.has(edge.to));
    const multiInternal = selectedNodes.size > 1 && selectedNodes.has(edge.from) && selectedNodes.has(edge.to);
    const connected = Boolean(selectedEndpoint || groupConnected || multiInternal);
    const isOut = selectedNodeId && edge.from === selectedNodeId;
    const isIn = selectedNodeId && edge.to === selectedNodeId;
    path.classList.toggle('dim', !connected);
    path.classList.toggle('connected', connected);
    path.classList.toggle('outbound', Boolean(isOut || groupConnected || multiInternal));
    path.classList.toggle('inbound', Boolean(isIn && !groupConnected && !multiInternal));
    if (label) {
      label.classList.toggle('dim', !connected);
      label.classList.toggle('connected', connected);
    }
  });
  inventory.querySelectorAll('[data-inventory-id]').forEach((row) => row.classList.toggle('selected', selectedNodes.has(row.dataset.inventoryId) || groupNodes.has(row.dataset.inventoryId)));
}
function clearSelectionHighlight() {
  nodeElements.forEach((element) => element.classList.remove('dim', 'connected', 'inbound', 'outbound', 'selected', 'group-member'));
  groupElements.forEach((element) => element.classList.remove('selected', 'group-member'));
  edgeRecords.forEach(({path, label}) => {
    path.classList.remove('dim', 'connected', 'inbound', 'outbound');
    if (label) label.classList.remove('dim', 'connected');
  });
  inventory.querySelectorAll('[data-inventory-id]').forEach((row) => row.classList.remove('selected'));
}
function layoutSnapshot() {
  const nodes = {};
  positions.forEach((position, id) => { nodes[id] = { x: Number(position.x.toFixed(1)), y: Number(position.y.toFixed(1)) }; });
  const groups = {};
  groupPositions.forEach((position, id) => {
    groups[id] = {
      x: Number(position.x.toFixed(1)),
      y: Number(position.y.toFixed(1)),
      width: Number(position.width.toFixed(1)),
      height: Number(position.height.toFixed(1))
    };
  });
  return { version: 2, title: data.title, generated_at: new Date().toISOString(), transform, collapsed_groups: [...collapsedGroups], groups, nodes };
}
function downloadLayout() {
  const blob = new Blob([JSON.stringify(layoutSnapshot(), null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'changegate-architecture-layout.json';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
function applyLayout(layout) {
  if (!layout || typeof layout !== 'object' || !layout.nodes) return;
  Object.entries(layout.nodes).forEach(([id, value]) => {
    if (positions.has(id) && Number.isFinite(value.x) && Number.isFinite(value.y)) setNodePosition(id, value.x, value.y);
  });
  Object.entries(layout.groups || {}).forEach(([id, value]) => {
    if (!groupPositions.has(id) || !Number.isFinite(value.x) || !Number.isFinite(value.y)) return;
    const position = groupPositions.get(id);
    position.x = value.x;
    position.y = value.y;
    if (Number.isFinite(value.width)) position.width = value.width;
    if (Number.isFinite(value.height)) position.height = value.height;
    const group = groupsById.get(id);
    if (group) {
      group.x = position.x;
      group.y = position.y;
      group.width = position.width;
      group.height = position.height;
    }
  });
  collapsedGroups.clear();
  (layout.collapsed_groups || []).forEach((id) => { if (groupsById.has(id)) collapsedGroups.add(id); });
  if (layout.transform && Number.isFinite(layout.transform.scale)) transform = layout.transform;
  draw();
  updateViewport();
}
function drawMiniMap() {
  if (!minimapContent) return;
  const width = 220;
  const height = 150;
  const scale = Math.min(width / Math.max(data.width, 1), height / Math.max(data.height, 1));
  minimapContent.innerHTML = data.groups.map((group) => {
    const position = groupPositions.get(group.id) || group;
    return '<rect class="mini-group" x="' + (position.x * scale).toFixed(1) + '" y="' + (position.y * scale).toFixed(1) + '" width="' + (position.width * scale).toFixed(1) + '" height="' + (position.height * scale).toFixed(1) + '" rx="2"></rect>';
  }).join('') +
    [...positions.entries()].map(([id, pos]) => isVisibleByCollapse(id) ? '<rect class="mini-node" x="' + (pos.x * scale).toFixed(1) + '" y="' + (pos.y * scale).toFixed(1) + '" width="' + Math.max(2, pos.width * scale).toFixed(1) + '" height="' + Math.max(2, pos.height * scale).toFixed(1) + '" rx="1"></rect>' : '').join('');
  updateMiniMapViewport();
}
function updateMiniMapViewport() {
  if (!minimapView || !canvasWrap) return;
  const scale = Math.min(220 / Math.max(data.width, 1), 150 / Math.max(data.height, 1));
  const x = Math.max(0, (-transform.x / transform.scale) * scale);
  const y = Math.max(0, (-transform.y / transform.scale) * scale);
  const width = Math.min(220, (canvasWrap.clientWidth / transform.scale) * scale);
  const height = Math.min(150, (canvasWrap.clientHeight / transform.scale) * scale);
  minimapView.setAttribute('x', x.toFixed(1));
  minimapView.setAttribute('y', y.toFixed(1));
  minimapView.setAttribute('width', Math.max(8, width).toFixed(1));
  minimapView.setAttribute('height', Math.max(8, height).toFixed(1));
}
document.querySelector('[data-action="zoom-in"]').addEventListener('click', () => zoomBy(1.15));
document.querySelector('[data-action="zoom-out"]').addEventListener('click', () => zoomBy(0.87));
document.querySelector('[data-action="reset"]').addEventListener('click', resetView);
document.querySelector('[data-action="download-layout"]').addEventListener('click', downloadLayout);
document.querySelector('[data-action="load-layout"]').addEventListener('click', () => layoutFile.click());
document.querySelector('[data-action="expand-groups"]').addEventListener('click', expandAllGroups);
controlsToggle.addEventListener('click', () => {
  const collapsed = document.body.classList.toggle('controls-collapsed');
  controlsToggle.textContent = collapsed ? 'Show controls' : 'Hide controls';
  controlsToggle.setAttribute('aria-expanded', String(!collapsed));
});
detailsClose.addEventListener('click', closeDrawer);
edgeLabelToggle.addEventListener('change', () => {
  document.body.classList.toggle('show-edge-labels', edgeLabelToggle.checked);
});
layoutFile.addEventListener('change', async () => {
  const file = layoutFile.files && layoutFile.files[0];
  if (!file) return;
  try { applyLayout(JSON.parse(await file.text())); } catch (error) { window.alert('Unable to load layout JSON: ' + error.message); }
  layoutFile.value = '';
});
window.addEventListener('keydown', (event) => {
  if (event.key === 'Meta') modifierKeys.meta = true;
  if (event.key === 'Control') modifierKeys.ctrl = true;
  if (event.key === 'Shift') modifierKeys.shift = true;
});
window.addEventListener('keyup', (event) => {
  if (event.key === 'Meta') modifierKeys.meta = false;
  if (event.key === 'Control') modifierKeys.ctrl = false;
  if (event.key === 'Shift') modifierKeys.shift = false;
});
window.addEventListener('blur', () => {
  modifierKeys.meta = false;
  modifierKeys.ctrl = false;
  modifierKeys.shift = false;
});
svg.addEventListener('wheel', (event) => { if (!event.ctrlKey && !event.metaKey) return; event.preventDefault(); zoomBy(event.deltaY < 0 ? 1.08 : 0.92); }, { passive: false });
svg.addEventListener('pointerdown', (event) => {
  if (event.target.closest && event.target.closest('.resource,.group')) return;
  selectedNodeId = '';
  selectedGroupId = '';
  selectedNodeIds.clear();
  clearSelectionHighlight();
  activePan = { x: event.clientX, y: event.clientY, tx: transform.x, ty: transform.y, element: svg };
  svg.classList.add('panning');
  capturePointer(svg, event.pointerId);
});
svg.addEventListener('pointermove', (event) => {
  if (activeDrag) {
    moveActiveNodeDrag(graphPoint(event));
    return;
  }
  if (activeGroupDrag) {
    moveActiveGroupDrag(graphPoint(event));
    return;
  }
  if (!activePan) return;
  transform.x = activePan.tx + (event.clientX - activePan.x);
  transform.y = activePan.ty + (event.clientY - activePan.y);
  updateViewport();
});
svg.addEventListener('pointerup', (event) => {
  if (activeDrag) {
    activeDrag.element.classList.remove('dragging');
    releasePointer(activeDrag.element, event.pointerId);
  }
  if (activeGroupDrag) {
    activeGroupDrag.element.classList.remove('dragging');
    releasePointer(activeGroupDrag.element, event.pointerId);
    if (activeGroupDrag.moved) draw();
  }
  if (activePan) releasePointer(activePan.element, event.pointerId);
  activeDrag = null;
  activeGroupDrag = null;
  activePan = null;
  svg.classList.remove('panning');
});
svg.addEventListener('pointercancel', () => {
  if (activeDrag) activeDrag.element.classList.remove('dragging');
  if (activeGroupDrag) activeGroupDrag.element.classList.remove('dragging');
  activeDrag = null;
  activeGroupDrag = null;
  activePan = null;
  svg.classList.remove('panning');
});
search.addEventListener('input', applyFilters);
canvasWrap.addEventListener('scroll', updateMiniMapViewport);
window.addEventListener('resize', updateMiniMapViewport);
minimap.addEventListener('click', (event) => {
  const rect = minimap.getBoundingClientRect();
  const scale = Math.min(220 / Math.max(data.width, 1), 150 / Math.max(data.height, 1));
  const graphX = (event.clientX - rect.left) / scale;
  const graphY = (event.clientY - rect.top) / scale;
  transform.x = (canvasWrap.clientWidth / 2) - graphX * transform.scale;
  transform.y = (canvasWrap.clientHeight / 2) - graphY * transform.scale;
  updateViewport();
});
draw();
updateViewport();
`
}
