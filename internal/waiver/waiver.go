// Package waiver manages reviewed finding suppressions.
package waiver

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	// Version is the current waiver file format version.
	Version    = 1
	dateLayout = "2006-01-02"
)

// File is the human-reviewable waiver YAML format.
type File struct {
	Version int      `json:"version" yaml:"version"`
	Waivers []Record `json:"waivers" yaml:"waivers"`
}

// Record describes one reviewed exception.
type Record struct {
	ID          string     `json:"id" yaml:"id"`
	RuleID      string     `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	Finding     string     `json:"finding,omitempty" yaml:"finding,omitempty"`
	Resource    string     `json:"resource,omitempty" yaml:"resource,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Owner       string     `json:"owner" yaml:"owner"`
	Reason      string     `json:"reason" yaml:"reason"`
	CreatedAt   string     `json:"created_at" yaml:"created_at"`
	ExpiresAt   string     `json:"expires_at" yaml:"expires_at"`
	Conditions  Conditions `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// Conditions narrows when a waiver can apply.
type Conditions struct {
	Environment         string `json:"environment,omitempty" yaml:"environment,omitempty"`
	EvidenceFingerprint string `json:"evidence_fingerprint,omitempty" yaml:"evidence_fingerprint,omitempty"`
	PolicyPackMajor     string `json:"policy_pack_major,omitempty" yaml:"policy_pack_major,omitempty"`
}

// ValidationOptions controls waiver governance validation.
type ValidationOptions struct {
	RequireExpiration bool
	MaxDurationDays   int
	Now               time.Time
}

// ValidationResult reports waiver file health.
type ValidationResult struct {
	Valid       bool               `json:"valid"`
	Diagnostics []model.Diagnostic `json:"diagnostics,omitempty"`
	Summary     Summary            `json:"summary"`
}

// Summary contains waiver counts.
type Summary struct {
	Total   int `json:"total"`
	Active  int `json:"active"`
	Expired int `json:"expired"`
	Broad   int `json:"broad"`
}

// Application describes a waiver match attempt.
type Application struct {
	WaiverID  string `json:"waiver_id"`
	FindingID string `json:"finding_id,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Applied   bool   `json:"applied"`
	Reason    string `json:"reason"`
}

// ReviewReport summarizes waiver application against current findings.
type ReviewReport struct {
	Applications []Application      `json:"applications"`
	Diagnostics  []model.Diagnostic `json:"diagnostics,omitempty"`
	Summary      ReviewSummary      `json:"summary"`
}

// ReviewSummary contains waiver review counts.
type ReviewSummary struct {
	Applied int `json:"applied"`
	Invalid int `json:"invalid"`
	Unused  int `json:"unused"`
}

// LoadFile loads a waiver YAML file.
func LoadFile(path string) (File, error) {
	file, err := os.Open(path)
	if err != nil {
		return File{}, fmt.Errorf("open waiver file %q: %w", path, err)
	}
	defer closeFile(file)
	return Load(file)
}

// Load decodes a waiver YAML file.
func Load(r io.Reader) (File, error) {
	var file File
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return File{}, fmt.Errorf("decode waiver file: %w", err)
	}
	if file.Version == 0 {
		file.Version = Version
	}
	sortRecords(file.Waivers)
	return file, nil
}

// Write emits deterministic waiver YAML.
func Write(w io.Writer, file File) error {
	if file.Version == 0 {
		file.Version = Version
	}
	sortRecords(file.Waivers)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(file); err != nil {
		closeErr := enc.Close()
		if closeErr != nil {
			return fmt.Errorf("%w; close encoder: %v", err, closeErr)
		}
		return err
	}
	return enc.Close()
}

// Validate checks governance and schema-level waiver requirements.
func Validate(file File, opts ValidationOptions) ValidationResult {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	var diagnostics []model.Diagnostic
	summary := Summary{Total: len(file.Waivers)}
	if file.Version != Version {
		diagnostics = append(diagnostics, errorDiagnostic("WAIVER_VERSION_UNSUPPORTED", fmt.Sprintf("waiver version must be %d", Version)))
	}
	ids := make(map[string]bool, len(file.Waivers))
	for _, record := range file.Waivers {
		if record.ID == "" {
			diagnostics = append(diagnostics, errorDiagnostic("WAIVER_ID_REQUIRED", "waiver id is required"))
		}
		if ids[record.ID] {
			diagnostics = append(diagnostics, errorDiagnostic("WAIVER_ID_DUPLICATE", "duplicate waiver id "+record.ID))
		}
		ids[record.ID] = true
		if record.Owner == "" {
			diagnostics = append(diagnostics, errorDiagnostic("WAIVER_OWNER_REQUIRED", "waiver "+record.ID+" requires owner"))
		}
		if record.Reason == "" {
			diagnostics = append(diagnostics, errorDiagnostic("WAIVER_REASON_REQUIRED", "waiver "+record.ID+" requires reason"))
		}
		if record.Rule() == "" && record.Resource == "" && record.Fingerprint == "" {
			diagnostics = append(diagnostics, errorDiagnostic("WAIVER_SCOPE_REQUIRED", "waiver "+record.ID+" requires rule_id, resource, or fingerprint scope"))
		}
		if record.Fingerprint == "" {
			summary.Broad++
			diagnostics = append(diagnostics, warningDiagnostic("WAIVER_BROAD_SCOPE", "waiver "+record.ID+" is broader than an exact fingerprint"))
		}
		expiresAt, ok := parseDate(record.ExpiresAt)
		if record.ExpiresAt == "" {
			if opts.RequireExpiration {
				diagnostics = append(diagnostics, errorDiagnostic("WAIVER_EXPIRATION_REQUIRED", "waiver "+record.ID+" requires expires_at"))
			}
		} else if !ok {
			diagnostics = append(diagnostics, errorDiagnostic("WAIVER_EXPIRATION_INVALID", "waiver "+record.ID+" expires_at must be YYYY-MM-DD"))
		} else if !opts.Now.Before(expiresAt.Add(24 * time.Hour)) {
			summary.Expired++
			diagnostics = append(diagnostics, warningDiagnostic("WAIVER_EXPIRED", "waiver "+record.ID+" has expired"))
		} else {
			summary.Active++
		}
		if opts.MaxDurationDays > 0 && record.CreatedAt != "" && record.ExpiresAt != "" {
			createdAt, createdOK := parseDate(record.CreatedAt)
			if createdOK && ok && expiresAt.Sub(createdAt) > time.Duration(opts.MaxDurationDays)*24*time.Hour {
				diagnostics = append(diagnostics, errorDiagnostic("WAIVER_DURATION_TOO_LONG", fmt.Sprintf("waiver %s exceeds max duration of %d days", record.ID, opts.MaxDurationDays)))
			}
		}
	}
	valid := true
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == model.DiagnosticError {
			valid = false
			break
		}
	}
	return ValidationResult{Valid: valid, Diagnostics: diagnostics, Summary: summary}
}

// Apply returns findings annotated with active waiver suppressions and an audit report.
func Apply(file File, findings []model.Finding, now time.Time, failExpired bool) ([]model.Finding, ReviewReport) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	report := ReviewReport{
		Applications: []Application{},
		Diagnostics:  []model.Diagnostic{},
	}
	used := make(map[string]bool, len(file.Waivers))
	for index := range out {
		finding := model.NormalizeFinding(out[index])
		for _, record := range file.Waivers {
			matches, reason := Matches(record, finding, now)
			app := Application{WaiverID: record.ID, FindingID: finding.ID, Resource: finding.ResourceAddress, Applied: matches, Reason: reason}
			if matches {
				finding.Suppressions = append(finding.Suppressions, model.Suppression{
					Kind:   "waiver",
					Reason: record.ID + ": " + record.Reason,
					Active: true,
				})
				finding.DecisionReasonCodes = append(finding.DecisionReasonCodes, model.ReasonSuppressed)
				finding.DecisionReasons = append(finding.DecisionReasons, model.DecisionReason{
					FindingID: finding.ID,
					Resource:  finding.ResourceAddress,
					Code:      model.ReasonSuppressed,
					Reason:    "suppressed by waiver " + record.ID,
				})
				used[record.ID] = true
				report.Summary.Applied++
				report.Applications = append(report.Applications, app)
				break
			}
			if reason != "scope did not match" {
				report.Summary.Invalid++
				report.Applications = append(report.Applications, app)
				if failExpired && reason == "waiver expired" {
					report.Diagnostics = append(report.Diagnostics, errorDiagnostic("WAIVER_EXPIRED", "waiver "+record.ID+" has expired"))
				}
			}
		}
		out[index] = finding
	}
	for _, record := range file.Waivers {
		if !used[record.ID] {
			report.Summary.Unused++
		}
	}
	return out, report
}

// Matches returns whether a waiver suppresses a finding and why.
func Matches(record Record, finding model.Finding, now time.Time) (bool, string) {
	if record.ExpiresAt != "" {
		expiresAt, ok := parseDate(record.ExpiresAt)
		if !ok {
			return false, "waiver expiration invalid"
		}
		if !now.Before(expiresAt.Add(24 * time.Hour)) {
			return false, "waiver expired"
		}
	}
	if record.Fingerprint != "" && record.Fingerprint != finding.Fingerprint {
		return false, "scope did not match"
	}
	if record.Rule() != "" && record.Rule() != finding.RuleID {
		return false, "scope did not match"
	}
	if record.Resource != "" && record.Resource != finding.ResourceAddress {
		return false, "scope did not match"
	}
	if record.Conditions.Environment != "" && record.Conditions.Environment != finding.Environment {
		return false, "environment condition did not match"
	}
	if record.Conditions.EvidenceFingerprint != "" && record.Conditions.EvidenceFingerprint != finding.Fingerprint {
		return false, "evidence fingerprint changed"
	}
	if record.Conditions.PolicyPackMajor != "" && finding.PolicyPackVersion != "" && !strings.HasPrefix(finding.PolicyPackVersion, record.Conditions.PolicyPackMajor+".") {
		return false, "policy pack major version changed"
	}
	return true, "waiver applied"
}

// PruneExpired removes expired waiver records.
func PruneExpired(file File, now time.Time) (File, []Record) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	kept := make([]Record, 0, len(file.Waivers))
	pruned := make([]Record, 0)
	for _, record := range file.Waivers {
		expiresAt, ok := parseDate(record.ExpiresAt)
		if ok && !now.Before(expiresAt.Add(24*time.Hour)) {
			pruned = append(pruned, record)
			continue
		}
		kept = append(kept, record)
	}
	file.Waivers = kept
	sortRecords(file.Waivers)
	return file, pruned
}

// NextID returns a stable next waiver ID.
func NextID(file File) string {
	maxID := 0
	for _, record := range file.Waivers {
		var number int
		if _, err := fmt.Sscanf(record.ID, "WVR-%03d", &number); err == nil && number > maxID {
			maxID = number
		}
	}
	return fmt.Sprintf("WVR-%03d", maxID+1)
}

// Rule returns the normalized rule scope.
func (r Record) Rule() string {
	if r.RuleID != "" {
		return r.RuleID
	}
	return r.Finding
}

func sortRecords(records []Record) {
	sort.SliceStable(records, func(i int, j int) bool {
		if records[i].ID != records[j].ID {
			return records[i].ID < records[j].ID
		}
		return records[i].Rule() < records[j].Rule()
	})
}

func parseDate(value string) (time.Time, bool) {
	parsed, err := time.Parse(dateLayout, value)
	return parsed, err == nil
}

func errorDiagnostic(code string, message string) model.Diagnostic {
	return model.Diagnostic{Severity: model.DiagnosticError, Code: code, Message: message}
}

func warningDiagnostic(code string, message string) model.Diagnostic {
	return model.Diagnostic{Severity: model.DiagnosticWarning, Code: code, Message: message}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}
