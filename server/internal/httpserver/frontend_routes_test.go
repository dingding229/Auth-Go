package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"authgo/internal/adminpath"
	"authgo/internal/portal"
)

// The remote check runs server tests before web tests on the same /src mount.
// Export the real, fully assembled dynamic Router table, not annotations or parsed Go text.
// The web test requires this file and verifies the source digest; it cannot fall
// back to a checked-in/stale inventory when this test has not run successfully.
func TestExportFrontendRouteContract(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "server", ".route-contract.json")
	if err := os.Remove(output); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	f := newPortalFixture(t, portal.Options{}, nil)
	type route struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	type routeContext struct {
		AdminPath string  `json:"admin_path"`
		Routes    []route `json:"routes"`
	}
	snapshot := func() routeContext {
		current, err := f.r.AdminPaths.Current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		routes := make([]route, 0)
		for _, registered := range f.r.Routes() {
			if strings.HasPrefix(registered.Path, "/api/") {
				routes = append(routes, route{registered.Method, registered.Path})
			}
		}
		sort.Slice(routes, func(i, j int) bool {
			return routes[i].Method+" "+routes[i].Path < routes[j].Method+" "+routes[j].Path
		})
		return routeContext{current, routes}
	}
	contexts := []routeContext{snapshot()}
	if contexts[0].AdminPath != "/admin" {
		t.Fatalf("fresh fixture admin path = %q", contexts[0].AdminPath)
	}
	if _, err := f.r.AdminPaths.Change(context.Background(), "/route-check", adminpath.Actor{Operator: "route-test"}); err != nil {
		t.Fatal(err)
	}
	contexts = append(contexts, snapshot())
	if contexts[1].AdminPath != "/route-check" {
		t.Fatalf("changed fixture admin path = %q", contexts[1].AdminPath)
	}
	var files []string
	for _, dir := range []string{"server", "web/src"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if strings.HasPrefix(rel, "web/src/") || strings.HasSuffix(rel, ".go") || rel == "server/internal/webui/routes.json" || rel == "server/go.mod" || rel == "server/go.sum" {
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(files)
	digest := sha256.New()
	for _, file := range files {
		contents, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = digest.Write([]byte(file + "\x00"))
		_, _ = digest.Write(contents)
		_, _ = digest.Write([]byte{0})
	}
	body, err := json.MarshalIndent(struct {
		Schema   int            `json:"schema"`
		Source   string         `json:"source"`
		Contexts []routeContext `json:"contexts"`
	}{2, hex.EncodeToString(digest.Sum(nil)), contexts}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// Rename only after the fixture and inventory are complete.
	tmp, err := os.CreateTemp(filepath.Dir(output), ".route-contract-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), output); err != nil {
		t.Fatal(err)
	}
	// Read the generated file inside the Go module so Go's test input cache
	// observes it. A fresh remote sync removes it, invalidating a cached export.
	if _, err := os.ReadFile(output); err != nil {
		t.Fatal(err)
	}
	t.Logf("exported %d actual API routes per default/custom context for web AST contract check", len(contexts[0].Routes))
}
