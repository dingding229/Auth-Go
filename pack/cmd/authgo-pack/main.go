package main

import (
	pack "authgo/pack"
	"os"
)

func main() { os.Exit(pack.Run(os.Args[1:], os.Stdout, os.Stderr)) }
