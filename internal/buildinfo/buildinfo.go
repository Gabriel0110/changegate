// Package buildinfo exposes build-time metadata for the ChangeGate binary.
package buildinfo

// These variables are intended to be overridden with -ldflags during release builds.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Info contains build metadata emitted by version commands and structured output.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Current returns the build metadata compiled into the binary.
func Current() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
	}
}
