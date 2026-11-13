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

// Quickstart introduces SDK integration for application developers.
//
//go:embed quickstart.md
var Quickstart string

// Customer is the standalone customer deployment and operating guide.
//
//go:embed customer.md
var Customer string

// Offline describes connectivity failures and signed grace periods.
//
//go:embed offline.md
var Offline string
