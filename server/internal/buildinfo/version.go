// Package buildinfo holds release metadata injected with go build -ldflags -X.
package buildinfo

var (
	Version = "1.0.2"
	Commit  = "unknown"
	BuiltAt = "unknown"
)
