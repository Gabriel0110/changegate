// Package model contains provider-neutral data structures used by ChangeGate.
package model

// Tool identifies the IaC engine that produced a plan JSON document.
type Tool string

const (
	// ToolUnknown means the plan producer could not be identified from JSON metadata.
	ToolUnknown Tool = "unknown"
	// ToolTerraform means the JSON appears to have been produced by Terraform.
	ToolTerraform Tool = "terraform"
	// ToolOpenTofu means the JSON appears to have been produced by OpenTofu.
	ToolOpenTofu Tool = "opentofu"
)

// DiagnosticSeverity describes parser diagnostic impact.
type DiagnosticSeverity string

const (
	// DiagnosticInfo is non-blocking informational context.
	DiagnosticInfo DiagnosticSeverity = "info"
	// DiagnosticWarning identifies compatibility or parsing concerns that did not stop ingestion.
	DiagnosticWarning DiagnosticSeverity = "warning"
	// DiagnosticError identifies a fatal ingestion problem.
	DiagnosticError DiagnosticSeverity = "error"
)

// Diagnostic captures non-finding parser and compatibility messages.
type Diagnostic struct {
	Severity DiagnosticSeverity `json:"severity"`
	Code     string             `json:"code"`
	Message  string             `json:"message"`
}

// Action is a normalized Terraform/OpenTofu resource action.
type Action string

const (
	// ActionCreate creates a resource.
	ActionCreate Action = "create"
	// ActionUpdate updates a resource in place.
	ActionUpdate Action = "update"
	// ActionDelete deletes a resource.
	ActionDelete Action = "delete"
	// ActionReplace replaces a resource by combining delete and create actions.
	ActionReplace Action = "replace"
	// ActionNoOp represents a planned no-op.
	ActionNoOp Action = "no-op"
	// ActionRead reads a data source.
	ActionRead Action = "read"
)

// Plan is ChangeGate's normalized representation of a plan JSON document.
type Plan struct {
	Tool             Tool                 `json:"tool"`
	FormatVersion    string               `json:"format_version"`
	TerraformVersion string               `json:"terraform_version,omitempty"`
	Provider         string               `json:"provider,omitempty"`
	Resources        []Resource           `json:"resources"`
	Changes          []Change             `json:"changes"`
	PriorResources   []Resource           `json:"prior_resources,omitempty"`
	Configuration    *Configuration       `json:"configuration,omitempty"`
	Diagnostics      []Diagnostic         `json:"diagnostics,omitempty"`
	Statistics       Statistics           `json:"statistics"`
	RawMetadata      map[string]string    `json:"raw_metadata,omitempty"`
	AWSResources     []AWSResourceSummary `json:"aws_resources,omitempty"`
}

// Statistics summarizes parser output without requiring callers to walk the whole model.
type Statistics struct {
	ResourceCount int `json:"resource_count"`
	ChangeCount   int `json:"change_count"`
}

// Resource is a provider-neutral planned or prior resource instance.
type Resource struct {
	Address    string            `json:"address"`
	Mode       string            `json:"mode,omitempty"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Provider   string            `json:"provider,omitempty"`
	ModulePath []string          `json:"module_path,omitempty"`
	Values     map[string]any    `json:"values,omitempty"`
	Sensitive  map[string]bool   `json:"sensitive,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	DependsOn  []string          `json:"depends_on,omitempty"`
}

// Change is a normalized resource change from the plan.
type Change struct {
	Address         string            `json:"address"`
	PreviousAddress string            `json:"previous_address,omitempty"`
	Mode            string            `json:"mode,omitempty"`
	Type            string            `json:"type"`
	Name            string            `json:"name"`
	Provider        string            `json:"provider,omitempty"`
	ModulePath      []string          `json:"module_path,omitempty"`
	Actions         []Action          `json:"actions"`
	Before          map[string]any    `json:"before,omitempty"`
	After           map[string]any    `json:"after,omitempty"`
	AfterUnknown    map[string]any    `json:"after_unknown,omitempty"`
	BeforeSensitive map[string]bool   `json:"before_sensitive,omitempty"`
	AfterSensitive  map[string]bool   `json:"after_sensitive,omitempty"`
	ReplacePaths    []string          `json:"replace_paths,omitempty"`
	ActionReason    string            `json:"action_reason,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// Configuration preserves configuration metadata and expression paths relevant to a plan.
type Configuration struct {
	ProviderConfigs map[string]ProviderConfig `json:"provider_configs,omitempty"`
	Resources       []ConfiguredResource      `json:"resources,omitempty"`
}

// ProviderConfig describes a Terraform/OpenTofu provider configuration entry.
type ProviderConfig struct {
	Name              string         `json:"name,omitempty"`
	FullName          string         `json:"full_name,omitempty"`
	Alias             string         `json:"alias,omitempty"`
	ModuleAddress     string         `json:"module_address,omitempty"`
	Expressions       map[string]any `json:"expressions,omitempty"`
	VersionConstraint string         `json:"version_constraint,omitempty"`
}

// ConfiguredResource preserves resource-level configuration expressions when available.
type ConfiguredResource struct {
	Address           string         `json:"address"`
	Mode              string         `json:"mode,omitempty"`
	Type              string         `json:"type"`
	Name              string         `json:"name"`
	ProviderConfigKey string         `json:"provider_config_key,omitempty"`
	ModulePath        []string       `json:"module_path,omitempty"`
	Expressions       map[string]any `json:"expressions,omitempty"`
	SchemaVersion     int            `json:"schema_version,omitempty"`
}

// AWSResourceSummary is a small typed AWS projection for currently supported resource families.
type AWSResourceSummary struct {
	Address string            `json:"address"`
	Type    string            `json:"type"`
	Name    string            `json:"name"`
	Region  string            `json:"region,omitempty"`
	Tags    map[string]string `json:"tags,omitempty"`
}
