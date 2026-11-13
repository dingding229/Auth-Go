// Package examplecheck keeps the remote server test gate aligned with CI's
// examples gate, including nested Go modules that server/go.mod cannot cover.
package examplecheck

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAllExampleModulesBuildVetAndTest(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository examples")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
	command := exec.Command("sh", filepath.Join(root, "scripts/check-examples.sh"))
	command.Dir = root
	output, err := command.CombinedOutput()
	t.Logf("%s", output)
	if err != nil {
		t.Fatalf("examples build/vet/test failed: %v", err)
	}
}
