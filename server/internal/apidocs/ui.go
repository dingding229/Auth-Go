package apidocs

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io"
	"io/fs"
	"sync"
)

// Embed only the UI we use and all accompanying licensing notices. No source
// maps or unused bundle variants. Decompress once, only if docs are requested.
//
//go:embed ui/*
var uiFiles embed.FS

func unzipUI(name string) ([]byte, error) {
	raw, err := uiFiles.ReadFile("ui/" + name + ".gz")
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

var (
	bundle = sync.OnceValues(func() ([]byte, error) { return unzipUI("swagger-ui-bundle.js") })
	styles = sync.OnceValues(func() ([]byte, error) { return unzipUI("swagger-ui.css") })
)

func UIAsset(name string) ([]byte, error) {
	switch name {
	case "swagger-ui-bundle.js":
		return bundle()
	case "swagger-ui.css":
		return styles()
	case "LICENSE", "NOTICE", "swagger-ui-bundle.js.LICENSE.txt":
		return uiFiles.ReadFile("ui/" + name)
	default:
		return nil, fs.ErrNotExist
	}
}
