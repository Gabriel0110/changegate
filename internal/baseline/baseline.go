// Package baseline stores and compares accepted existing ChangeGate findings.
package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
)

const (
	// Version is the current baseline file format version.
	Version = 1
	// Generator identifies this baseline producer.
	Generator = "changegate"
)

// File is the deterministic baseline JSON format.
type File struct {
	Version            int               `json:"version"`
	CreatedAt          string            `json:"created_at"`
	ExpiresAt          string            `json:"expires_at,omitempty"`
	Generator          string            `json:"generator"`
	PolicyPackVersions map[string]string `json:"policy_pack_versions"`
	Summary            Summary           `json:"summary"`
	Findings           []Entry           `json:"findings"`
}

// Summary describes baseline entry counts.
type Summary struct {
	Findings int `json:"findings"`
}

// Entry is a non-secret snapshot of one accepted finding.
type Entry struct {
	Fingerprint       string             `json:"fingerprint"`
	DeduplicationKey  string             `json:"deduplication_key"`
	RuleID            string             `json:"rule_id"`
	Resource          string             `json:"resource"`
	Provider          string             `json:"provider,omitempty"`
	Category          model.RiskCategory `json:"category"`
	Severity          model.Severity     `json:"severity"`
	Confidence        model.Confidence   `json:"confidence"`
	Title             string             `json:"title"`
	ResourceMovedFrom string             `json:"resource_moved_from,omitempty"`
}

// DiffResult compares current findings to a baseline.
type DiffResult struct {
	BaselinePath string      `json:"baseline_path,omitempty"`
	New          []Entry     `json:"new"`
	Unchanged    []Entry     `json:"unchanged"`
	Changed      []Entry     `json:"changed"`
	Stale        []Entry     `json:"stale"`
	Summary      DiffSummary `json:"summary"`
	Warnings     []string    `json:"warnings,omitempty"`
}

// DiffSummary describes diff counts.
type DiffSummary struct {
	New       int `json:"new"`
	Unchanged int `json:"unchanged"`
	Changed   int `json:"changed"`
	Stale     int `json:"stale"`
}

// Build creates a sorted baseline from findings and policy pack metadata.
func Build(findings []model.Finding, packs []rules.PolicyPack, now time.Time, expiresAt *time.Time) File {
	entries := EntriesFromFindings(findings)
	file := File{
		Version:            Version,
		CreatedAt:          now.UTC().Format(time.RFC3339),
		Generator:          Generator,
		PolicyPackVersions: packVersions(packs),
		Summary:            Summary{Findings: len(entries)},
		Findings:           entries,
	}
	if expiresAt != nil {
		file.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	}
	return file
}

// EntriesFromFindings returns deterministic non-secret baseline entries.
func EntriesFromFindings(findings []model.Finding) []Entry {
	entries := make([]Entry, 0, len(findings))
	for _, finding := range findings {
		normalized := model.NormalizeFinding(finding)
		entries = append(entries, Entry{
			Fingerprint:      normalized.Fingerprint,
			DeduplicationKey: normalized.DeduplicationKey,
			RuleID:           normalized.RuleID,
			Resource:         normalized.ResourceAddress,
			Provider:         normalized.Provider,
			Category:         normalized.Category,
			Severity:         normalized.Severity,
			Confidence:       normalized.Confidence,
			Title:            normalized.Title,
		})
	}
	sortEntries(entries)
	return entries
}

// LoadFile loads and validates a baseline file.
func LoadFile(path string) (File, error) {
	file, err := os.Open(path)
	if err != nil {
		return File{}, fmt.Errorf("open baseline %q: %w", path, err)
	}
	defer closeFile(file)
	return Load(file)
}

// Load decodes and validates a baseline.
func Load(r io.Reader) (File, error) {
	var file File
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return File{}, fmt.Errorf("decode baseline: %w", err)
	}
	if file.Version != Version {
		return File{}, fmt.Errorf("baseline version must be %d", Version)
	}
	sortEntries(file.Findings)
	file.Summary.Findings = len(file.Findings)
	return file, nil
}

// Write writes a deterministic baseline JSON file.
func Write(w io.Writer, file File) error {
	sortEntries(file.Findings)
	file.Summary.Findings = len(file.Findings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(file)
}

// Fingerprints returns active fingerprints from the baseline.
func Fingerprints(file File) map[string]bool {
	out := make(map[string]bool, len(file.Findings))
	for _, finding := range file.Findings {
		out[finding.Fingerprint] = true
	}
	return out
}

// Diagnostics returns freshness warnings for a baseline file.
func Diagnostics(file File, now time.Time, maxAgeDays int, requireExpiration bool) []string {
	var warnings []string
	if requireExpiration && file.ExpiresAt == "" {
		warnings = append(warnings, "baseline has no expires_at value")
	}
	if file.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, file.ExpiresAt)
		if err != nil {
			warnings = append(warnings, "baseline expires_at is not RFC3339")
		} else if !now.UTC().Before(expiresAt) {
			warnings = append(warnings, "baseline has expired")
		}
	}
	if maxAgeDays > 0 && file.CreatedAt != "" {
		createdAt, err := time.Parse(time.RFC3339, file.CreatedAt)
		if err != nil {
			warnings = append(warnings, "baseline created_at is not RFC3339")
		} else if now.UTC().Sub(createdAt.UTC()) > time.Duration(maxAgeDays)*24*time.Hour {
			warnings = append(warnings, fmt.Sprintf("baseline is older than %d days", maxAgeDays))
		}
	}
	return warnings
}

// Diff compares current findings to a baseline.
func Diff(file File, current []model.Finding, now time.Time, maxAgeDays int, requireExpiration bool) DiffResult {
	result := DiffResult{
		New:       make([]Entry, 0),
		Unchanged: make([]Entry, 0),
		Changed:   make([]Entry, 0),
		Stale:     make([]Entry, 0),
		Warnings:  Diagnostics(file, now, maxAgeDays, requireExpiration),
	}
	currentEntries := EntriesFromFindings(current)
	byFingerprint := make(map[string]Entry, len(file.Findings))
	byRenameKey := make(map[string]Entry, len(file.Findings))
	for _, entry := range file.Findings {
		byFingerprint[entry.Fingerprint] = entry
		byRenameKey[renameKey(entry)] = entry
	}
	seenBaseline := make(map[string]bool, len(file.Findings))
	for _, entry := range currentEntries {
		if existing, ok := byFingerprint[entry.Fingerprint]; ok {
			result.Unchanged = append(result.Unchanged, entry)
			seenBaseline[existing.Fingerprint] = true
			continue
		}
		if existing, ok := byRenameKey[renameKey(entry)]; ok {
			entry.ResourceMovedFrom = existing.Resource
			result.Changed = append(result.Changed, entry)
			seenBaseline[existing.Fingerprint] = true
			continue
		}
		result.New = append(result.New, entry)
	}
	for _, entry := range file.Findings {
		if !seenBaseline[entry.Fingerprint] {
			result.Stale = append(result.Stale, entry)
		}
	}
	sortEntries(result.New)
	sortEntries(result.Unchanged)
	sortEntries(result.Changed)
	sortEntries(result.Stale)
	result.Summary = DiffSummary{
		New:       len(result.New),
		Unchanged: len(result.Unchanged),
		Changed:   len(result.Changed),
		Stale:     len(result.Stale),
	}
	return result
}

func packVersions(packs []rules.PolicyPack) map[string]string {
	out := make(map[string]string, len(packs))
	for _, pack := range packs {
		out[pack.ID] = pack.Version
	}
	return out
}

func renameKey(entry Entry) string {
	return string(entry.Category) + "|" + entry.RuleID + "|" + entry.Provider + "|" + string(entry.Severity) + "|" + string(entry.Confidence)
}

func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i int, j int) bool {
		left := entries[i]
		right := entries[j]
		for _, less := range []int{
			compare(left.RuleID, right.RuleID),
			compare(left.Resource, right.Resource),
			compare(string(left.Severity), string(right.Severity)),
			compare(left.Fingerprint, right.Fingerprint),
		} {
			if less < 0 {
				return true
			}
			if less > 0 {
				return false
			}
		}
		return false
	})
}

func compare(a string, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}
