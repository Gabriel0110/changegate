package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func sortedChanges(plan *model.Plan) []model.Change {
	if plan == nil {
		return nil
	}
	out := append([]model.Change(nil), plan.Changes...)
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].Address < out[j].Address
	})
	return out
}

func sortedNodes(g *graph.Graph) map[graph.ResourceID]*graph.Node {
	if g == nil {
		return nil
	}
	return g.Nodes
}

func ev(resource string, path string, value any, message string) model.Evidence {
	return model.Evidence{
		Type:     "rule",
		Resource: resource,
		Path:     path,
		Value:    value,
		Message:  message,
	}
}

func exposureEvidence(g *graph.Graph, from graph.ResourceID, to graph.ResourceID, resource string) []model.Evidence {
	if g == nil {
		return []model.Evidence{ev(resource, "graph", to, "resource is internet exposed")}
	}
	lines, ok := g.ExplainConnection(from, to)
	if !ok || len(lines) == 0 {
		return []model.Evidence{ev(resource, "graph", to, "resource is internet exposed")}
	}
	out := make([]model.Evidence, 0, len(lines))
	for _, line := range lines {
		out = append(out, ev(resource, "graph", to, line))
	}
	return out
}

func looksAdmin(node *graph.Node) bool {
	if node == nil {
		return false
	}
	text := strings.ToLower(node.Address + " " + node.Name + " " + node.Tags["service"] + " " + node.Tags["role"])
	return strings.Contains(text, "admin") || strings.Contains(text, "backoffice") || strings.Contains(text, "console")
}

func isInternal(node *graph.Node) bool {
	if node == nil {
		return false
	}
	for _, key := range []string{"exposure", "visibility", "tier", "service"} {
		if strings.EqualFold(node.Tags[key], "internal") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(node.Address), "internal")
}

func adminPorts() map[int]bool {
	return map[int]bool{22: true, 3389: true, 5432: true, 3306: true, 6379: true, 9200: true, 9300: true, 6443: true}
}

func dbPorts() map[int]bool {
	return map[int]bool{5432: true, 3306: true, 1433: true, 1521: true, 27017: true, 6379: true, 9042: true}
}

func securityGroupPortFindings(input RuleInput, meta Metadata, ports map[int]bool, message string, remediation string) []model.Finding {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_security_group" && change.Type != "aws_vpc_security_group_ingress_rule" {
			continue
		}
		if !publicCIDRInChange(change) {
			continue
		}
		if !portsTouched(change, ports) {
			continue
		}
		out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{
			ev(change.Address, "ingress", "0.0.0.0/0", message),
		}, remediation))
	}
	return out
}

func publicCIDRInChange(change model.Change) bool {
	text := asJSON(change.After)
	return strings.Contains(text, "0.0.0.0/0") || strings.Contains(text, "::/0")
}

func portsTouched(change model.Change, ports map[int]bool) bool {
	for _, key := range []string{"from_port", "to_port"} {
		if ports[intValue(change.After[key])] {
			return true
		}
	}
	text := asJSON(change.After)
	for port := range ports {
		if strings.Contains(text, strconv.Itoa(port)) {
			return true
		}
	}
	return false
}

func envFromChange(change model.Change) string {
	for _, key := range []string{"env", "environment", "stage"} {
		value := strings.ToLower(change.Tags[key])
		if value == "" {
			if tags, ok := change.After["tags"].(map[string]any); ok {
				value = strings.ToLower(asString(tags[key]))
			}
		}
		switch value {
		case "prod", "production":
			return "production"
		case "stage", "staging":
			return "staging"
		case "dev", "development":
			return "development"
		}
	}
	return ""
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func truthy(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		out, _ := typed.Int64()
		return int(out)
	case string:
		out, _ := strconv.Atoi(typed)
		return out
	default:
		return 0
	}
}

func asJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return strings.ToLower(string(encoded))
}

func isRDS(typ string) bool {
	return typ == "aws_db_instance" || typ == "aws_rds_cluster"
}

func isReplacement(change model.Change) bool {
	if len(change.Actions) == 1 && change.Actions[0] == model.ActionReplace {
		return true
	}
	hasCreate := false
	hasDelete := false
	for _, action := range change.Actions {
		hasCreate = hasCreate || action == model.ActionCreate
		hasDelete = hasDelete || action == model.ActionDelete
	}
	return hasCreate && hasDelete
}

func statefulType(typ string) bool {
	switch typ {
	case "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_efs_file_system", "aws_dynamodb_table", "aws_elasticache_cluster":
		return true
	default:
		return false
	}
}

func encryptionDisabled(values map[string]any) bool {
	for _, key := range []string{"storage_encrypted", "encrypted", "server_side_encryption_configuration"} {
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case bool:
				return !typed
			case nil:
				return true
			case []any:
				return len(typed) == 0
			case string:
				return typed == "" || strings.EqualFold(typed, "false")
			}
		}
	}
	return false
}

func isSensitiveBucket(change model.Change) bool {
	text := strings.ToLower(change.Address + " " + change.Name + " " + fmt.Sprint(change.Tags) + " " + asJSON(change.After["tags"]))
	return strings.Contains(text, "prod") || strings.Contains(text, "sensitive") || strings.Contains(text, "logs") || strings.Contains(text, "backup")
}

func isSensitiveNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	switch node.Type {
	case "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_secretsmanager_secret", "aws_dynamodb_table":
		return true
	default:
		return false
	}
}

func hasResourceType(g *graph.Graph, typ string) bool {
	if g == nil {
		return false
	}
	for _, node := range g.Nodes {
		if node.Type == typ {
			return true
		}
	}
	return false
}

func hasAnyChangedType(plan *model.Plan, types ...string) bool {
	set := make(map[string]bool, len(types))
	for _, typ := range types {
		set[typ] = true
	}
	for _, change := range sortedChanges(plan) {
		if set[change.Type] {
			return true
		}
	}
	return false
}

func adminRoleIDs(g *graph.Graph) []graph.ResourceID {
	out := make([]graph.ResourceID, 0)
	for id, node := range g.Nodes {
		if node.Type == "aws_iam_role" && strings.Contains(strings.ToLower(node.Address+" "+node.Name), "admin") {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i int, j int) bool { return out[i] < out[j] })
	return out
}

func policyTextFindings(input RuleInput, meta Metadata, types []string, needles []string, path string, message string, remediation string) []model.Finding {
	typeSet := make(map[string]bool, len(types))
	for _, typ := range types {
		typeSet[typ] = true
	}
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if !typeSet[change.Type] {
			continue
		}
		text := normalizePolicyText(asString(change.After[path]))
		if text == "" || text == "null" {
			text = normalizePolicyText(asJSON(change.After))
		}
		ok := true
		for _, needle := range needles {
			if !strings.Contains(text, normalizePolicyText(needle)) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, path, "(policy)", message)}, remediation))
		}
	}
	return out
}

func normalizePolicyText(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "\\", "")
	return value
}
