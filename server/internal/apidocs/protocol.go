package apidocs

import _ "embed"

// Protocol is the embedded client protocol specification and its single source of truth.
//
//go:embed protocol.md
var Protocol string

// Docker is the embedded Docker integration specification and its single source of truth.
//
//go:embed docker.md
var Docker string
