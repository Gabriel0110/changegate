// Package cloudcontext enriches plan-only findings with optional cloud snapshots.
package cloudcontext

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	// Version is the current cloud context snapshot version.
	Version = 2
	// ProviderAWS is the AWS cloud context provider name.
	ProviderAWS = "aws"
)

// Snapshot is an offline, redacted cloud context file.
type Snapshot struct {
	Version       int                `json:"version"`
	Provider      string             `json:"provider"`
	GeneratedAt   string             `json:"generated_at"`
	Account       Account            `json:"account"`
	Regions       []Region           `json:"regions,omitempty"`
	Capabilities  Capabilities       `json:"capabilities,omitempty"`
	Network       ResourceSet        `json:"network,omitempty"`
	IAM           ResourceSet        `json:"iam,omitempty"`
	Data          ResourceSet        `json:"data,omitempty"`
	Compute       ResourceSet        `json:"compute,omitempty"`
	Edge          ResourceSet        `json:"edge,omitempty"`
	Relationships []Relationship     `json:"relationships,omitempty"`
	Diagnostics   []model.Diagnostic `json:"diagnostics,omitempty"`
}

// MarshalJSON emits compact v2 snapshots by omitting empty domain sections.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type snapshotJSON struct {
		Version       int                `json:"version"`
		Provider      string             `json:"provider"`
		GeneratedAt   string             `json:"generated_at"`
		Account       Account            `json:"account"`
		Regions       []Region           `json:"regions,omitempty"`
		Capabilities  *Capabilities      `json:"capabilities,omitempty"`
		Network       *ResourceSet       `json:"network,omitempty"`
		IAM           *ResourceSet       `json:"iam,omitempty"`
		Data          *ResourceSet       `json:"data,omitempty"`
		Compute       *ResourceSet       `json:"compute,omitempty"`
		Edge          *ResourceSet       `json:"edge,omitempty"`
		Relationships []Relationship     `json:"relationships,omitempty"`
		Diagnostics   []model.Diagnostic `json:"diagnostics,omitempty"`
	}
	out := snapshotJSON{
		Version:       s.Version,
		Provider:      s.Provider,
		GeneratedAt:   s.GeneratedAt,
		Account:       s.Account,
		Regions:       s.Regions,
		Relationships: s.Relationships,
		Diagnostics:   s.Diagnostics,
	}
	if !capabilitiesEmpty(s.Capabilities) {
		out.Capabilities = &s.Capabilities
	}
	if !resourceSetEmpty(s.Network) {
		out.Network = &s.Network
	}
	if !resourceSetEmpty(s.IAM) {
		out.IAM = &s.IAM
	}
	if !resourceSetEmpty(s.Data) {
		out.Data = &s.Data
	}
	if !resourceSetEmpty(s.Compute) {
		out.Compute = &s.Compute
	}
	if !resourceSetEmpty(s.Edge) {
		out.Edge = &s.Edge
	}
	return json.Marshal(out)
}

// Account describes non-secret account identity metadata.
type Account struct {
	ID    string `json:"id,omitempty"`
	ARN   string `json:"arn,omitempty"`
	Alias string `json:"alias,omitempty"`
}

// Region describes enabled region metadata.
type Region struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// Capabilities records read-only permissions represented in a snapshot.
type Capabilities struct {
	Identity       bool `json:"identity"`
	Network        bool `json:"network"`
	SecurityGroups bool `json:"security_groups"`
	IAM            bool `json:"iam"`
	S3             bool `json:"s3"`
	RDS            bool `json:"rds"`
	KMS            bool `json:"kms"`
	SecretsManager bool `json:"secrets_manager"`
	EKS            bool `json:"eks"`
}

// Resource contains v2 provider resource identity and context.
type Resource struct {
	TerraformAddress      string            `json:"terraform_address,omitempty"`
	ARN                   string            `json:"arn,omitempty"`
	ID                    string            `json:"id,omitempty"`
	AccountID             string            `json:"account_id,omitempty"`
	Type                  string            `json:"type,omitempty"`
	Region                string            `json:"region,omitempty"`
	Tags                  map[string]string `json:"tags,omitempty"`
	Sensitivity           Sensitivity       `json:"sensitivity,omitempty"`
	Attributes            map[string]string `json:"attributes,omitempty"`
	Public                *bool             `json:"public,omitempty"`
	EncryptionEnabled     *bool             `json:"encryption_enabled,omitempty"`
	PublicAccessBlocked   *bool             `json:"public_access_blocked,omitempty"`
	DeletionProtection    *bool             `json:"deletion_protection,omitempty"`
	EndpointPublicAccess  *bool             `json:"endpoint_public_access,omitempty"`
	SensitiveData         bool              `json:"sensitive_data,omitempty"`
	RelatedSensitiveData  []string          `json:"related_sensitive_data,omitempty"`
	CompensatingControls  []string          `json:"compensating_controls,omitempty"`
	ObservedPolicyActions []string          `json:"observed_policy_actions,omitempty"`
	Drift                 map[string]string `json:"drift,omitempty"`
}

// MarshalJSON omits empty nested resource metadata.
func (r Resource) MarshalJSON() ([]byte, error) {
	type resourceJSON struct {
		TerraformAddress      string            `json:"terraform_address,omitempty"`
		ARN                   string            `json:"arn,omitempty"`
		ID                    string            `json:"id,omitempty"`
		AccountID             string            `json:"account_id,omitempty"`
		Type                  string            `json:"type,omitempty"`
		Region                string            `json:"region,omitempty"`
		Tags                  map[string]string `json:"tags,omitempty"`
		Sensitivity           *Sensitivity      `json:"sensitivity,omitempty"`
		Attributes            map[string]string `json:"attributes,omitempty"`
		Public                *bool             `json:"public,omitempty"`
		EncryptionEnabled     *bool             `json:"encryption_enabled,omitempty"`
		PublicAccessBlocked   *bool             `json:"public_access_blocked,omitempty"`
		DeletionProtection    *bool             `json:"deletion_protection,omitempty"`
		EndpointPublicAccess  *bool             `json:"endpoint_public_access,omitempty"`
		SensitiveData         bool              `json:"sensitive_data,omitempty"`
		RelatedSensitiveData  []string          `json:"related_sensitive_data,omitempty"`
		CompensatingControls  []string          `json:"compensating_controls,omitempty"`
		ObservedPolicyActions []string          `json:"observed_policy_actions,omitempty"`
		Drift                 map[string]string `json:"drift,omitempty"`
	}
	out := resourceJSON{
		TerraformAddress:      r.TerraformAddress,
		ARN:                   r.ARN,
		ID:                    r.ID,
		AccountID:             r.AccountID,
		Type:                  r.Type,
		Region:                r.Region,
		Tags:                  r.Tags,
		Attributes:            r.Attributes,
		Public:                r.Public,
		EncryptionEnabled:     r.EncryptionEnabled,
		PublicAccessBlocked:   r.PublicAccessBlocked,
		DeletionProtection:    r.DeletionProtection,
		EndpointPublicAccess:  r.EndpointPublicAccess,
		SensitiveData:         r.SensitiveData,
		RelatedSensitiveData:  r.RelatedSensitiveData,
		CompensatingControls:  r.CompensatingControls,
		ObservedPolicyActions: r.ObservedPolicyActions,
		Drift:                 r.Drift,
	}
	if !sensitivityEmpty(r.Sensitivity) {
		out.Sensitivity = &r.Sensitivity
	}
	return json.Marshal(out)
}

// ResourceSet groups live cloud resources by provider domain.
type ResourceSet struct {
	Resources map[string]Resource `json:"resources,omitempty"`
}

// Sensitivity describes whether a cloud resource should be treated as sensitive.
type Sensitivity struct {
	Data   bool   `json:"data,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Relationship describes a v2 cloud-context edge with provenance.
type Relationship struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Type       string `json:"type"`
	Source     string `json:"source,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// Identity is safe AWS identity metadata detected from environment.
type Identity struct {
	Detected  bool   `json:"detected"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
	Profile   string `json:"profile,omitempty"`
}

// LoadFile loads a cloud context snapshot.
func LoadFile(path string) (Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open context file %q: %w", path, err)
	}
	defer closeFile(file)
	return Load(file)
}

// Load decodes and normalizes a context snapshot.
func Load(r io.Reader) (Snapshot, error) {
	var snapshot Snapshot
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode context file: %w", err)
	}
	if snapshot.Version != Version {
		return Snapshot{}, fmt.Errorf("context version must be %d", Version)
	}
	if snapshot.Provider != ProviderAWS {
		return Snapshot{}, fmt.Errorf("unsupported context provider %q", snapshot.Provider)
	}
	Normalize(&snapshot)
	return snapshot, nil
}

// Write emits deterministic context JSON.
func Write(w io.Writer, snapshot Snapshot) error {
	if snapshot.Version == 0 {
		snapshot.Version = Version
	}
	if snapshot.Provider == "" {
		snapshot.Provider = ProviderAWS
	}
	Normalize(&snapshot)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snapshot)
}

// Normalize redacts and sorts all cloud context fields in place.
func Normalize(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	if snapshot.Version == 0 {
		snapshot.Version = Version
	}
	normalizeResourceSet(&snapshot.Network)
	normalizeResourceSet(&snapshot.IAM)
	normalizeResourceSet(&snapshot.Data)
	normalizeResourceSet(&snapshot.Compute)
	normalizeResourceSet(&snapshot.Edge)
	for index, relationship := range snapshot.Relationships {
		relationship.Source = redactValue("relationship.source", relationship.Source)
		snapshot.Relationships[index] = relationship
	}
	sort.Slice(snapshot.Relationships, func(i int, j int) bool {
		left := snapshot.Relationships[i]
		right := snapshot.Relationships[j]
		return left.From+"\x00"+left.To+"\x00"+left.Type < right.From+"\x00"+right.To+"\x00"+right.Type
	})
}

// NewAWSSnapshot returns an empty redacted AWS snapshot with identity metadata.
func NewAWSSnapshot(identity Identity, now time.Time) Snapshot {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	regions := []Region{}
	if identity.Region != "" {
		regions = append(regions, Region{Name: identity.Region, Enabled: true})
	}
	return Snapshot{
		Version:     Version,
		Provider:    ProviderAWS,
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Account: Account{
			ID: identity.AccountID,
		},
		Regions: regions,
		Diagnostics: []model.Diagnostic{{
			Severity: model.DiagnosticWarning,
			Code:     "CLOUD_CONTEXT_SNAPSHOT_EMPTY",
			Message:  "snapshot contains identity metadata only; add read-only AWS inventory data for enrichment",
		}},
	}
}

// DetectAWSIdentity returns non-secret AWS metadata from environment variables.
func DetectAWSIdentity(env map[string]string) Identity {
	identity := Identity{
		AccountID: firstNonEmpty(env["AWS_ACCOUNT_ID"], env["AWS_ACCOUNT"]),
		Region:    firstNonEmpty(env["AWS_REGION"], env["AWS_DEFAULT_REGION"]),
		Profile:   env["AWS_PROFILE"],
	}
	identity.Detected = identity.AccountID != "" || identity.Region != "" || identity.Profile != ""
	return identity
}

// ValidatePermissions reports missing read-only context capability groups.
func ValidatePermissions(snapshot Snapshot) []model.Diagnostic {
	required := map[string]bool{
		"identity":        snapshot.Capabilities.Identity,
		"network":         snapshot.Capabilities.Network,
		"security_groups": snapshot.Capabilities.SecurityGroups,
		"iam":             snapshot.Capabilities.IAM,
		"s3":              snapshot.Capabilities.S3,
		"rds":             snapshot.Capabilities.RDS,
		"kms":             snapshot.Capabilities.KMS,
		"secrets_manager": snapshot.Capabilities.SecretsManager,
		"eks":             snapshot.Capabilities.EKS,
	}
	keys := make([]string, 0, len(required))
	for key := range required {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var diagnostics []model.Diagnostic
	for _, key := range keys {
		if !required[key] {
			diagnostics = append(diagnostics, model.Diagnostic{
				Severity: model.DiagnosticWarning,
				Code:     "CLOUD_CONTEXT_PERMISSION_MISSING",
				Message:  "AWS context snapshot lacks " + key + " read capability",
			})
		}
	}
	return diagnostics
}

// EnrichFindings adds cloud-context evidence and context-driven severity changes.
func EnrichFindings(findings []model.Finding, snapshot Snapshot) ([]model.Finding, []model.Diagnostic) {
	Normalize(&snapshot)
	out := make([]model.Finding, 0, len(findings))
	diagnostics := append([]model.Diagnostic{}, snapshot.Diagnostics...)
	resources := indexedResources(snapshot)
	for _, finding := range findings {
		current := model.NormalizeFinding(finding)
		resource, ok := resources[current.ResourceAddress]
		if !ok {
			out = append(out, current)
			continue
		}
		current.Evidence = append(current.Evidence, evidence(current.ResourceAddress, "cloud_context.account", snapshot.Account.ID, "AWS account context attached"))
		if resource.Region != "" {
			current.Evidence = append(current.Evidence, evidence(current.ResourceAddress, "cloud_context.region", resource.Region, "AWS region context attached"))
		}
		for key, value := range resource.Drift {
			current.Evidence = append(current.Evidence, evidence(current.ResourceAddress, "cloud_context.drift."+key, value, "actual cloud state differs from plan context"))
			current = upgrade(current, "cloud context found drift: "+key)
		}
		if len(resource.RelatedSensitiveData) > 0 || resource.SensitiveData {
			current.Evidence = append(current.Evidence, evidence(current.ResourceAddress, "cloud_context.sensitive_data", strings.Join(resource.RelatedSensitiveData, ","), "cloud context found sensitive data relationship"))
			current = upgrade(current, "cloud context found sensitive data relationship")
		}
		if expectedPublic(resource) && isPublicExposure(current) {
			current.Evidence = append(current.Evidence, evidence(current.ResourceAddress, "cloud_context.compensating_controls", strings.Join(resource.CompensatingControls, ","), "cloud context found compensating controls for expected public resource"))
			current = downgrade(current, "cloud context found expected public edge controls")
		}
		if resource.EncryptionEnabled != nil && !*resource.EncryptionEnabled {
			current.Evidence = append(current.Evidence, evidence(current.ResourceAddress, "cloud_context.encryption_enabled", false, "actual cloud resource encryption is disabled"))
			current = upgrade(current, "cloud context found encryption disabled in actual state")
		}
		if resource.PublicAccessBlocked != nil && !*resource.PublicAccessBlocked && strings.Contains(strings.ToLower(current.RuleID), "s3") {
			current.Evidence = append(current.Evidence, evidence(current.ResourceAddress, "cloud_context.public_access_blocked", false, "actual S3 public access block is disabled"))
			current = upgrade(current, "cloud context found S3 public access block disabled")
		}
		out = append(out, model.NormalizeFinding(current))
	}
	return out, diagnostics
}

func indexedResources(snapshot Snapshot) map[string]Resource {
	out := make(map[string]Resource)
	for _, set := range []ResourceSet{snapshot.Network, snapshot.IAM, snapshot.Data, snapshot.Compute, snapshot.Edge} {
		for key, resource := range set.Resources {
			addResourceIndex(out, key, resource)
		}
	}
	return out
}

func addResourceIndex(index map[string]Resource, key string, resource Resource) {
	for _, candidate := range []string{
		key,
		resource.TerraformAddress,
		resource.ARN,
		resource.ID,
		resource.Attributes["name"],
		resource.Attributes["resource_id"],
		resource.Tags["Name"],
		resource.Tags["name"],
		resource.Tags["terraform_address"],
		resource.Tags["TerraformAddress"],
	} {
		if candidate == "" {
			continue
		}
		if _, exists := index[candidate]; !exists {
			index[candidate] = resource
		}
	}
}

func capabilitiesEmpty(capabilities Capabilities) bool {
	return !capabilities.Identity &&
		!capabilities.Network &&
		!capabilities.SecurityGroups &&
		!capabilities.IAM &&
		!capabilities.S3 &&
		!capabilities.RDS &&
		!capabilities.KMS &&
		!capabilities.SecretsManager &&
		!capabilities.EKS
}

func resourceSetEmpty(set ResourceSet) bool {
	return len(set.Resources) == 0
}

func sensitivityEmpty(sensitivity Sensitivity) bool {
	return !sensitivity.Data && sensitivity.Reason == ""
}

// ReadOnlyPolicyTemplate returns an IAM policy template for context collection.
func ReadOnlyPolicyTemplate() string {
	return `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAttachedRolePolicies",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "rds:DescribeDBInstances",
        "kms:DescribeKey",
        "secretsmanager:DescribeSecret",
        "eks:DescribeCluster"
      ],
      "Resource": "*"
    }
  ]
}
`
}

func expectedPublic(resource Resource) bool {
	for _, control := range resource.CompensatingControls {
		switch strings.ToLower(control) {
		case "expected_public_tls_edge", "edge_tls", "waf", "cloudfront_oac", "ip_allowlist":
			return true
		}
	}
	return false
}

func isPublicExposure(finding model.Finding) bool {
	return finding.Category == model.RiskCategoryPublicExposure || strings.Contains(strings.ToLower(finding.RuleID), "public")
}

func downgrade(f model.Finding, reason string) model.Finding {
	if f.Severity == model.SeverityHigh {
		f.Severity = model.SeverityMedium
	}
	if f.Confidence == model.ConfidenceHigh {
		f.Confidence = model.ConfidenceMedium
	}
	f.DecisionReasonCodes = append(f.DecisionReasonCodes, model.ReasonDowngraded)
	f.DecisionReasons = append(f.DecisionReasons, model.DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: model.ReasonDowngraded, Reason: reason})
	return f
}

func upgrade(f model.Finding, reason string) model.Finding {
	if f.Severity == model.SeverityHigh {
		f.Severity = model.SeverityCritical
	}
	f.DecisionReasonCodes = append(f.DecisionReasonCodes, model.ReasonUpgraded)
	f.DecisionReasons = append(f.DecisionReasons, model.DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: model.ReasonUpgraded, Reason: reason})
	return f
}

func evidence(resource string, path string, value any, message string) model.Evidence {
	return model.Evidence{Type: "cloud_context", Resource: resource, Path: path, Value: value, Message: message}
}

func redactTags(tags map[string]string) map[string]string {
	return redactMap(tags)
}

func normalizeResourceSet(set *ResourceSet) {
	if set.Resources == nil {
		return
	}
	for key, resource := range set.Resources {
		resource.TerraformAddress = firstNonEmpty(resource.TerraformAddress, key)
		resource.Tags = redactTags(resource.Tags)
		resource.Attributes = redactMap(resource.Attributes)
		resource.RelatedSensitiveData = redactStringSlice("related_sensitive_data", resource.RelatedSensitiveData)
		resource.CompensatingControls = redactStringSlice("compensating_controls", resource.CompensatingControls)
		resource.ObservedPolicyActions = redactStringSlice("observed_policy_actions", resource.ObservedPolicyActions)
		resource.Drift = redactMap(resource.Drift)
		resource.Sensitivity.Reason = redactValue("sensitivity.reason", resource.Sensitivity.Reason)
		if resource.Sensitivity.Data {
			resource.SensitiveData = true
		}
		set.Resources[key] = resource
	}
}

func redactMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = redactValue(key, value)
	}
	return out
}

func redactStringSlice(key string, values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = redactValue(key, value)
	}
	return out
}

func redactValue(key string, value string) string {
	if looksSensitive(key) || looksSensitive(value) {
		return "(sensitive)"
	}
	return value
}

func looksSensitive(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "private")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}
