package risktest

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// RenderText renders a developer-friendly risk test result.
func RenderText(result Result) string {
	var b strings.Builder
	for _, manifest := range result.Manifests {
		if manifest.Error != "" {
			fmt.Fprintf(&b, "ERROR %s\n", manifest.Path)
			fmt.Fprintf(&b, "  error: %s\n", manifest.Error)
			continue
		}
		for _, test := range manifest.Tests {
			switch {
			case test.Passed:
				fmt.Fprintf(&b, "PASS %s\n", test.Name)
			case test.Error != "":
				fmt.Fprintf(&b, "ERROR %s\n", test.Name)
				fmt.Fprintf(&b, "  error: %s\n", test.Error)
			default:
				fmt.Fprintf(&b, "FAIL %s\n", test.Name)
				for _, failure := range test.Failures {
					fmt.Fprintf(&b, "  %s: %s\n", failure.Assertion, failure.Message)
				}
			}
		}
	}
	if len(result.Manifests) > 0 {
		b.WriteString("\n")
	}
	status := "failed"
	if result.Passed {
		status = "passed"
	}
	fmt.Fprintf(&b, "Risk tests: %s\n", status)
	fmt.Fprintf(&b, "Manifests: %d\n", result.Summary.Manifests)
	fmt.Fprintf(&b, "Tests: %d passed, %d failed, %d errors\n", result.Summary.Passed, result.Summary.Failed, result.Summary.Errors)
	return b.String()
}

// RenderJUnit renders risk test results as JUnit XML for CI systems.
func RenderJUnit(result Result) ([]byte, error) {
	suites := make([]junitTestsuite, 0, len(result.Manifests))
	totalTests := 0
	totalFailures := 0
	totalErrors := 0
	for _, manifest := range result.Manifests {
		suite := junitTestsuite{Name: manifest.Path}
		if manifest.Error != "" {
			suite.Tests = 1
			suite.Errors = 1
			suite.Testcases = []junitTestcase{{
				Name:      "manifest",
				Classname: manifest.Path,
				Error:     &junitError{Message: manifest.Error, Type: "manifest"},
			}}
			totalTests += suite.Tests
			totalErrors += suite.Errors
			suites = append(suites, suite)
			continue
		}
		suite.Tests = len(manifest.Tests)
		suite.Testcases = make([]junitTestcase, 0, len(manifest.Tests))
		for _, test := range manifest.Tests {
			tc := junitTestcase{Name: test.Name, Classname: manifest.Path}
			switch {
			case test.Error != "":
				suite.Errors++
				tc.Error = &junitError{Message: test.Error, Type: "execution"}
			case len(test.Failures) > 0:
				suite.Failures++
				tc.Failure = &junitFailure{Message: fmt.Sprintf("%d assertion failure(s)", len(test.Failures)), Type: "assertion", Body: failureBody(test.Failures)}
			}
			suite.Testcases = append(suite.Testcases, tc)
		}
		totalTests += suite.Tests
		totalFailures += suite.Failures
		totalErrors += suite.Errors
		suites = append(suites, suite)
	}
	body, err := xml.MarshalIndent(junitTestsuites{
		Name:     "changegate.risk-tests",
		Tests:    totalTests,
		Failures: totalFailures,
		Errors:   totalErrors,
		Suites:   suites,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Testcases []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitError   `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
}

func failureBody(failures []Failure) string {
	var b strings.Builder
	for _, failure := range failures {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s: %s", failure.Assertion, failure.Message)
	}
	return b.String()
}

// PassedTestNames returns stable passed test names for summaries.
func PassedTestNames(result Result) []string {
	names := make([]string, 0, result.Summary.Passed)
	for _, manifest := range result.Manifests {
		for _, test := range manifest.Tests {
			if test.Passed {
				names = append(names, test.Name)
				continue
			}
		}
	}
	return names
}
