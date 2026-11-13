package apidocs

import (
	"errors"
	"io/fs"
	"testing"
)

func TestUIAssets(t *testing.T) {
	for _, name := range []string{"swagger-ui-bundle.js", "swagger-ui.css", "LICENSE", "NOTICE", "swagger-ui-bundle.js.LICENSE.txt"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for range 2 {
				raw, err := UIAsset(name)
				if err != nil || len(raw) == 0 || raw[0] == 0x1f {
					t.Fatalf("bad asset %s: %v", name, err)
				}
			}
		})
	}
	if _, err := UIAsset("../api.go"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("unexpected asset accessible")
	}
}
