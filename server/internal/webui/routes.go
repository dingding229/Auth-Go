package webui

import (
	"embed"
	"encoding/json"
	"io/fs"
	"strings"
)

// This is the same path authority imported by the Vue router. Management entries
// are relative to the runtime address; public entries are full absolute paths.
//
//go:embed routes.json
var routeData embed.FS

type PageRoute struct {
	Path  string `json:"path"`
	Scope string `json:"scope"`
}

func pageRoutes() []PageRoute {
	raw, err := routeData.ReadFile("routes.json")
	if err != nil {
		panic(err)
	}
	var entries []PageRoute
	if err = json.Unmarshal(raw, &entries); err != nil {
		panic(err)
	}
	return entries
}
func PublicPaths() []string {
	var out []string
	for _, entry := range pageRoutes() {
		if entry.Scope == "public" && !strings.Contains(entry.Path, ":pathMatch") {
			out = append(out, entry.Path)
		}
	}
	// The filesystem mount is a real public namespace too. Derive its roots
	// from the embedded build, so a future public/fonts directory cannot be
	// shadowed by a chosen management path.
	if files, err := fs.Sub(embedded, "dist"); err == nil {
		if entries, err := fs.ReadDir(files, "."); err == nil {
			for _, entry := range entries {
				if entry.Name() != "placeholder.txt" {
					out = append(out, "/"+entry.Name())
				}
			}
		}
	}
	return out
}
func knownPage(path string) bool {
	for _, entry := range pageRoutes() {
		pattern := entry.Path
		if entry.Scope == "admin" {
			pattern = "/admin" + pattern
		}
		if strings.Contains(pattern, ":pathMatch") {
			continue
		}
		if matchPage(pattern, path) {
			return true
		}
	}
	return false
}
func matchPage(pattern, path string) bool {
	a := strings.Split(strings.Trim(pattern, "/"), "/")
	b := strings.Split(strings.Trim(path, "/"), "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], ":") {
			if b[i] == "" {
				return false
			}
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
