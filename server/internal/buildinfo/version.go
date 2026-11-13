// Package buildinfo holds release metadata injected with go build -ldflags -X.
package buildinfo

var (
	Version = "1.0.0"
	Commit  = "unknown"
	BuiltAt = "unknown"
)
