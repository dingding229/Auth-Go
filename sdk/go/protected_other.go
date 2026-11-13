//go:build !linux

package sdk

import (
	"fmt"
	"io"
)

func hardenProtected() {}
func RunProtected(args, environment []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "整体加密启动桩仅支持Linux")
	return ExitLicense
}
