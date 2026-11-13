// authgo-stub replaces itself with a fully authenticated executable in memory.
package main

import (
	sdk "authgo/sdk"
	"os"
)

func main() { os.Exit(sdk.RunProtected(os.Args, os.Environ(), os.Stderr)) }
