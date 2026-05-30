package cli

import "errors"

const (
	exitAllowed             = 0
	exitBlocked             = 1
	exitUsage               = 2
	exitInputParsing        = 3
	exitPolicyConfiguration = 4
	exitCloudContext        = 5
	exitInternal            = 6
	exitUnsupported         = 7
)

// ExitError is a user-facing error with a stable process exit code.
type ExitError struct {
	Code int
	Kind string
	Err  error
	Fix  string
}

// Error returns the user-facing error message.
func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func newExitError(code int, kind string, message string, fix string) *ExitError {
	return &ExitError{
		Code: code,
		Kind: kind,
		Err:  errors.New(message),
		Fix:  fix,
	}
}

func exitCodeMeanings() map[int]string {
	return map[int]string{
		exitAllowed:             "scan completed; deploy allowed",
		exitBlocked:             "scan completed; deploy blocked by policy",
		exitUsage:               "invalid CLI usage or invalid arguments",
		exitInputParsing:        "input parsing error",
		exitPolicyConfiguration: "policy or configuration error",
		exitCloudContext:        "cloud-context or authentication error",
		exitInternal:            "internal scanner error",
		exitUnsupported:         "unsupported plan, schema, or provider version",
	}
}

func usageError(message string, fix string) *ExitError {
	return newExitError(exitUsage, "usage", message, fix)
}

func inputError(message string, fix string) *ExitError {
	return newExitError(exitInputParsing, "input", message, fix)
}

func internalError(message string, fix string) *ExitError {
	return newExitError(exitInternal, "internal", message, fix)
}

func unsupportedError(message string, fix string) *ExitError {
	return newExitError(exitUnsupported, "unsupported", message, fix)
}
