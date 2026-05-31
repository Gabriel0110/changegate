// Package terraform loads Terraform/OpenTofu show -json plan output.
package terraform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

const supportedFormatMajor = "1"
const allSensitiveMarker = "__changegate_all_sensitive__"

// Load reads Terraform/OpenTofu plan JSON from r and returns a normalized plan model.
func Load(r io.Reader) (*model.Plan, error) {
	var raw rawPlan

	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, &ParseError{
			Kind: "invalid_json",
			Err:  fmt.Errorf("decode plan JSON: %w", err),
		}
	}

	if raw.FormatVersion == "" {
		return nil, &ParseError{
			Kind: "missing_format_version",
			Err:  fmt.Errorf("plan JSON is missing format_version"),
		}
	}

	diagnostics, err := checkFormatVersion(raw.FormatVersion)
	if err != nil {
		return nil, err
	}

	plan := &model.Plan{
		Tool:             detectTool(raw),
		FormatVersion:    raw.FormatVersion,
		TerraformVersion: raw.TerraformVersion,
		Diagnostics:      diagnostics,
		RawMetadata:      raw.metadata(),
	}

	plannedResources := normalizeValuesResources(raw.PlannedValues, nil)
	plan.Resources = plannedResources
	plan.PriorResources = normalizeValuesResources(raw.PriorState.Values, nil)
	plan.Changes = normalizeChanges(raw.ResourceChanges)
	plan.Configuration = normalizeConfiguration(raw.Configuration)
	plan.Provider = firstProvider(plannedResources, plan.Changes)
	plan.AWSResources = normalizeAWSResources(plannedResources)
	plan.Statistics = model.Statistics{
		ResourceCount: len(plan.Resources),
		ChangeCount:   len(plan.Changes),
	}

	return plan, nil
}

// ParseError describes a plan ingestion failure with a stable kind for CLI mapping.
type ParseError struct {
	Kind string
	Err  error
}

// Error returns the user-facing parser error.
func (e *ParseError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Unwrap returns the underlying parser error.
func (e *ParseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type rawPlan struct {
	FormatVersion    string              `json:"format_version"`
	TerraformVersion string              `json:"terraform_version"`
	OpenTofuVersion  string              `json:"opentofu_version"`
	TofuVersion      string              `json:"tofu_version"`
	PlannedValues    rawValues           `json:"planned_values"`
	PriorState       rawState            `json:"prior_state"`
	Configuration    rawConfiguration    `json:"configuration"`
	ResourceChanges  []rawResourceChange `json:"resource_changes"`
}

func (p rawPlan) metadata() map[string]string {
	out := make(map[string]string)
	if p.TerraformVersion != "" {
		out["terraform_version"] = p.TerraformVersion
	}
	if p.OpenTofuVersion != "" {
		out["opentofu_version"] = p.OpenTofuVersion
	}
	if p.TofuVersion != "" {
		out["tofu_version"] = p.TofuVersion
	}
	return out
}

type rawState struct {
	Values rawValues `json:"values"`
}

type rawValues struct {
	RootModule rawModule `json:"root_module"`
}

type rawModule struct {
	Address      string        `json:"address"`
	Resources    []rawResource `json:"resources"`
	ChildModules []rawModule   `json:"child_modules"`
}

type rawResource struct {
	Address         string          `json:"address"`
	Mode            string          `json:"mode"`
	Type            string          `json:"type"`
	Name            string          `json:"name"`
	ProviderName    string          `json:"provider_name"`
	ProviderConfig  string          `json:"provider_config_key"`
	SchemaVersion   int             `json:"schema_version"`
	Values          map[string]any  `json:"values"`
	SensitiveValues rawSensitiveMap `json:"sensitive_values"`
	DependsOn       []string        `json:"depends_on"`
}

type rawResourceChange struct {
	Address         string    `json:"address"`
	PreviousAddress string    `json:"previous_address"`
	ModuleAddress   string    `json:"module_address"`
	Mode            string    `json:"mode"`
	Type            string    `json:"type"`
	Name            string    `json:"name"`
	ProviderName    string    `json:"provider_name"`
	Change          rawChange `json:"change"`
	ActionReason    string    `json:"action_reason"`
}

type rawChange struct {
	Actions         []string        `json:"actions"`
	Before          map[string]any  `json:"before"`
	After           map[string]any  `json:"after"`
	AfterUnknown    map[string]any  `json:"after_unknown"`
	BeforeSensitive rawSensitiveMap `json:"before_sensitive"`
	AfterSensitive  rawSensitiveMap `json:"after_sensitive"`
	ReplacePaths    []any           `json:"replace_paths"`
}

type rawSensitiveMap map[string]any

func (m *rawSensitiveMap) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("false")) {
		*m = nil
		return nil
	}
	if bytes.Equal(trimmed, []byte("true")) {
		*m = rawSensitiveMap{allSensitiveMarker: true}
		return nil
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*m = decoded
	return nil
}

type rawConfiguration struct {
	ProviderConfig map[string]rawProviderConfig `json:"provider_config"`
	RootModule     rawConfigModule              `json:"root_module"`
}

type rawProviderConfig struct {
	Name              string         `json:"name"`
	FullName          string         `json:"full_name"`
	Alias             string         `json:"alias"`
	ModuleAddress     string         `json:"module_address"`
	Expressions       map[string]any `json:"expressions"`
	VersionConstraint string         `json:"version_constraint"`
}

type rawConfigModule struct {
	Address      string              `json:"address"`
	Resources    []rawConfigResource `json:"resources"`
	ModuleCalls  map[string]rawCall  `json:"module_calls"`
	ChildModules []rawConfigModule   `json:"child_modules"`
}

type rawCall struct {
	Source  string          `json:"source"`
	Module  rawConfigModule `json:"module"`
	Address string          `json:"address"`
}

type rawConfigResource struct {
	Address           string         `json:"address"`
	Mode              string         `json:"mode"`
	Type              string         `json:"type"`
	Name              string         `json:"name"`
	ProviderConfigKey string         `json:"provider_config_key"`
	Expressions       map[string]any `json:"expressions"`
	SchemaVersion     int            `json:"schema_version"`
}

func checkFormatVersion(formatVersion string) ([]model.Diagnostic, error) {
	parts := strings.Split(formatVersion, ".")
	if len(parts) == 0 || parts[0] == "" {
		return nil, &ParseError{
			Kind: "unsupported_format_version",
			Err:  fmt.Errorf("unsupported plan format_version %q", formatVersion),
		}
	}

	if parts[0] != supportedFormatMajor {
		return nil, &ParseError{
			Kind: "unsupported_format_version",
			Err:  fmt.Errorf("unsupported plan format_version %q; supported major version is %s.x", formatVersion, supportedFormatMajor),
		}
	}

	if len(parts) > 1 && parts[1] != "0" {
		return []model.Diagnostic{{
			Severity: model.DiagnosticWarning,
			Code:     "PLAN_FORMAT_MINOR_VERSION",
			Message:  "Plan format minor version is newer than the parser was built against; unknown properties will be ignored.",
		}}, nil
	}

	return nil, nil
}

func detectTool(raw rawPlan) model.Tool {
	if raw.OpenTofuVersion != "" || raw.TofuVersion != "" {
		return model.ToolOpenTofu
	}
	if strings.Contains(strings.ToLower(raw.TerraformVersion), "opentofu") {
		return model.ToolOpenTofu
	}
	if raw.TerraformVersion != "" {
		return model.ToolTerraform
	}
	return model.ToolUnknown
}

func normalizeValuesResources(values rawValues, inheritedSensitive map[string]any) []model.Resource {
	resources := make([]model.Resource, 0)
	walkValuesModule(values.RootModule, inheritedSensitive, &resources)
	return resources
}

func walkValuesModule(module rawModule, inheritedSensitive map[string]any, resources *[]model.Resource) {
	for _, resource := range module.Resources {
		sensitive := mergeSensitive(inheritedSensitive, resource.SensitiveValues)
		values := redactByMarkers(resource.Values, sensitive)
		*resources = append(*resources, model.Resource{
			Address:    resource.Address,
			Mode:       resource.Mode,
			Type:       resource.Type,
			Name:       resource.Name,
			Provider:   resource.ProviderName,
			ModulePath: modulePath(resource.Address, module.Address),
			Values:     values,
			Sensitive:  flattenSensitive(sensitive),
			Tags:       extractTags(values),
			DependsOn:  sortedStrings(resource.DependsOn),
		})
	}

	for _, child := range module.ChildModules {
		walkValuesModule(child, inheritedSensitive, resources)
	}
}

func normalizeChanges(changes []rawResourceChange) []model.Change {
	out := make([]model.Change, 0, len(changes))
	for _, change := range changes {
		beforeSensitive := flattenSensitive(change.Change.BeforeSensitive)
		afterSensitive := flattenSensitive(change.Change.AfterSensitive)
		after := redactByMarkers(change.Change.After, change.Change.AfterSensitive)
		before := redactByMarkers(change.Change.Before, change.Change.BeforeSensitive)

		out = append(out, model.Change{
			Address:         change.Address,
			PreviousAddress: change.PreviousAddress,
			Mode:            change.Mode,
			Type:            change.Type,
			Name:            change.Name,
			Provider:        change.ProviderName,
			ModulePath:      modulePath(change.Address, change.ModuleAddress),
			Actions:         normalizeActions(change.Change.Actions),
			Before:          before,
			After:           after,
			AfterUnknown:    copyMap(change.Change.AfterUnknown),
			BeforeSensitive: beforeSensitive,
			AfterSensitive:  afterSensitive,
			ReplacePaths:    normalizeReplacePaths(change.Change.ReplacePaths),
			ActionReason:    change.ActionReason,
			Tags:            extractTags(after),
		})
	}
	return out
}

func normalizeActions(actions []string) []model.Action {
	if len(actions) == 2 && containsString(actions, "delete") && containsString(actions, "create") {
		return []model.Action{model.ActionReplace}
	}

	out := make([]model.Action, 0, len(actions))
	for _, action := range actions {
		switch action {
		case "create":
			out = append(out, model.ActionCreate)
		case "update":
			out = append(out, model.ActionUpdate)
		case "delete":
			out = append(out, model.ActionDelete)
		case "no-op":
			out = append(out, model.ActionNoOp)
		case "read":
			out = append(out, model.ActionRead)
		default:
			out = append(out, model.Action(action))
		}
	}
	return out
}

func normalizeConfiguration(raw rawConfiguration) *model.Configuration {
	if len(raw.ProviderConfig) == 0 && len(raw.RootModule.Resources) == 0 && len(raw.RootModule.ModuleCalls) == 0 && len(raw.RootModule.ChildModules) == 0 {
		return nil
	}

	config := &model.Configuration{
		ProviderConfigs: make(map[string]model.ProviderConfig, len(raw.ProviderConfig)),
	}
	for key, provider := range raw.ProviderConfig {
		config.ProviderConfigs[key] = model.ProviderConfig{
			Name:              provider.Name,
			FullName:          provider.FullName,
			Alias:             provider.Alias,
			ModuleAddress:     provider.ModuleAddress,
			Expressions:       copyMap(provider.Expressions),
			VersionConstraint: provider.VersionConstraint,
		}
	}

	config.Resources = flattenConfigResources(raw.RootModule)
	return config
}

func flattenConfigResources(module rawConfigModule) []model.ConfiguredResource {
	resources := make([]model.ConfiguredResource, 0)
	walkConfigModule(module, &resources)
	return resources
}

func walkConfigModule(module rawConfigModule, resources *[]model.ConfiguredResource) {
	for _, resource := range module.Resources {
		*resources = append(*resources, model.ConfiguredResource{
			Address:           resource.Address,
			Mode:              resource.Mode,
			Type:              resource.Type,
			Name:              resource.Name,
			ProviderConfigKey: resource.ProviderConfigKey,
			ModulePath:        modulePath(resource.Address, module.Address),
			Expressions:       copyMap(resource.Expressions),
			SchemaVersion:     resource.SchemaVersion,
		})
	}

	for name, call := range module.ModuleCalls {
		child := call.Module
		if child.Address == "" {
			child.Address = "module." + name
		}
		walkConfigModule(child, resources)
	}

	for _, child := range module.ChildModules {
		walkConfigModule(child, resources)
	}
}

func normalizeAWSResources(resources []model.Resource) []model.AWSResourceSummary {
	out := make([]model.AWSResourceSummary, 0)
	for _, resource := range resources {
		if !strings.HasPrefix(resource.Type, "aws_") {
			continue
		}
		out = append(out, model.AWSResourceSummary{
			Address: resource.Address,
			Type:    resource.Type,
			Name:    resource.Name,
			Region:  stringValue(resource.Values["region"]),
			Tags:    resource.Tags,
		})
	}
	return out
}

func normalizeReplacePaths(paths []any) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, stringifyPath(path))
	}
	return out
}

func stringifyPath(value any) string {
	switch typed := value.(type) {
	case []any:
		parts := make([]string, 0, len(typed))
		for _, part := range typed {
			parts = append(parts, stringifyPath(part))
		}
		return strings.Join(parts, ".")
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprint(typed)
	}
}

func modulePath(address string, moduleAddress string) []string {
	if moduleAddress == "" {
		moduleAddress = deriveModuleAddress(address)
	}
	if moduleAddress == "" {
		return nil
	}

	parts := strings.Split(moduleAddress, ".")
	path := make([]string, 0, len(parts)/2)
	for index := 0; index < len(parts)-1; index += 2 {
		if parts[index] == "module" {
			path = append(path, parts[index+1])
		}
	}
	return path
}

func deriveModuleAddress(address string) string {
	parts := strings.Split(address, ".")
	modules := make([]string, 0)
	for index := 0; index < len(parts)-1; index += 2 {
		if parts[index] != "module" {
			break
		}
		modules = append(modules, "module."+parts[index+1])
	}
	return strings.Join(modules, ".")
}

func firstProvider(resources []model.Resource, changes []model.Change) string {
	for _, resource := range resources {
		if resource.Provider != "" {
			return resource.Provider
		}
	}
	for _, change := range changes {
		if change.Provider != "" {
			return change.Provider
		}
	}
	return ""
}

func mergeSensitive(base map[string]any, override map[string]any) map[string]any {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	merged := copyMap(base)
	if merged == nil {
		merged = make(map[string]any, len(override))
	}
	for key, value := range override {
		merged[key] = value
	}
	return merged
}

func redactByMarkers(values map[string]any, markers map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	if markers[allSensitiveMarker] == true {
		for key := range values {
			out[key] = "(sensitive)"
		}
		return out
	}
	for key, value := range values {
		marker, marked := markers[key]
		if marked && marker == true {
			out[key] = "(sensitive)"
			continue
		}
		if marked {
			if nestedValues, ok := value.(map[string]any); ok {
				if nestedMarkers, ok := marker.(map[string]any); ok {
					out[key] = redactByMarkers(nestedValues, nestedMarkers)
					continue
				}
			}
			if nestedValues, ok := value.([]any); ok {
				out[key] = redactListByMarkers(nestedValues, marker)
				continue
			}
		}
		out[key] = redactValue(value)
	}
	return out
}

func redactListByMarkers(values []any, marker any) []any {
	out := make([]any, len(values))
	markerList, listMarkers := marker.([]any)
	for index, value := range values {
		if listMarkers && index < len(markerList) {
			if markerList[index] == true {
				out[index] = "(sensitive)"
				continue
			}
			if nestedValue, ok := value.(map[string]any); ok {
				if nestedMarker, ok := markerList[index].(map[string]any); ok {
					out[index] = redactByMarkers(nestedValue, nestedMarker)
					continue
				}
			}
		}
		out[index] = redactValue(value)
	}
	return out
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactByMarkers(typed, nil)
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = redactValue(item)
		}
		return out
	default:
		return typed
	}
}

func flattenSensitive(markers map[string]any) map[string]bool {
	if len(markers) == 0 {
		return nil
	}
	out := make(map[string]bool)
	walkSensitive("", markers, out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func walkSensitive(prefix string, markers map[string]any, out map[string]bool) {
	for key, value := range markers {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		switch typed := value.(type) {
		case bool:
			if typed {
				out[path] = true
			}
		case map[string]any:
			walkSensitive(path, typed, out)
		case []any:
			for index, item := range typed {
				itemPath := path + "." + strconv.Itoa(index)
				switch nested := item.(type) {
				case bool:
					if nested {
						out[itemPath] = true
					}
				case map[string]any:
					walkSensitive(itemPath, nested, out)
				}
			}
		}
	}
}

func extractTags(values map[string]any) map[string]string {
	raw, ok := values["tags"]
	if !ok {
		raw, ok = values["tags_all"]
	}
	if !ok {
		return nil
	}

	tagMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}

	tags := make(map[string]string, len(tagMap))
	for key, value := range tagMap {
		if text := stringValue(value); text != "" {
			tags[key] = text
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func copyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(in); err != nil {
		return nil
	}
	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	out := make(map[string]any)
	if err := dec.Decode(&out); err != nil {
		return nil
	}
	return out
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
