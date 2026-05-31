package risktest

import (
	"fmt"
	"strings"
)

// RenderText renders a developer-friendly risk test result.
func RenderText(result Result) string {
	var b strings.Builder
	status := "failed"
	if result.Passed {
		status = "passed"
	}
	fmt.Fprintf(&b, "Risk tests: %s\n", status)
	fmt.Fprintf(&b, "Manifests: %d\n", result.Summary.Manifests)
	fmt.Fprintf(&b, "Tests: %d passed, %d failed, %d errors\n", result.Summary.Passed, result.Summary.Failed, result.Summary.Errors)
	for _, manifest := range result.Manifests {
		if manifest.Error != "" {
			fmt.Fprintf(&b, "\n%s\n", manifest.Path)
			fmt.Fprintf(&b, "  error: %s\n", manifest.Error)
			continue
		}
		for _, test := range manifest.Tests {
			if test.Passed {
				continue
			}
			fmt.Fprintf(&b, "\n%s: %s\n", manifest.Path, test.Name)
			if test.Error != "" {
				fmt.Fprintf(&b, "  error: %s\n", test.Error)
				continue
			}
			for _, failure := range test.Failures {
				fmt.Fprintf(&b, "  - %s: %s\n", failure.Assertion, failure.Message)
			}
		}
	}
	return b.String()
}
