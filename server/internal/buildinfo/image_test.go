package buildinfo

import "testing"

func TestPackImageTag(t *testing.T) {
	original := Version
	defer func() { Version = original }()
	for version, want := range map[string]string{"1.0.2": "1.0.2", "v1.0.2": "1.0.2", "dev": "latest", "1.0.2-rc.1": "latest", "01.0.2": "latest", "1.0.2+test": "latest", "v1.0.2\n": "latest"} {
		Version = version
		if got := PackImageTag(); got != want {
			t.Fatal(version, got, want)
		}
	}
}
