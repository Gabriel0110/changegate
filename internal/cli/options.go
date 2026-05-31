package cli

import "slices"

var validFormats = []string{"table", "json", "sarif", "junit", "markdown", "github-step-summary", "github-annotations", "gitlab-code-quality", "pr-comment", "audit-bundle", "dot", "mermaid"}
var validModes = []string{"block", "warn", "audit"}

type options struct {
	format   string
	outPath  string
	policy   string
	mode     string
	cacheDir string

	noColor  bool
	quiet    bool
	verbose  bool
	debug    bool
	exitCode int
}

func defaultOptions() *options {
	return &options{
		format: "table",
		mode:   "block",
	}
}

func validateEnum(name string, value string, allowed []string) error {
	if slices.Contains(allowed, value) {
		return nil
	}
	return usageError(
		name+" must be one of: "+joinHuman(allowed),
		"Run changegate --help to view supported flags.",
	)
}

func joinHuman(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += ", " + value
	}
	return out
}
