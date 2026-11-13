package adminpath

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"authgo/internal/response"
	"github.com/gin-gonic/gin"
)

type requestKey struct{}
type requestState struct {
	Path     string
	Original string
	Missing  bool
}

// Router projects private canonical management routes onto the live address.
// Keeping one Gin engine means rate limiting, auditing and authentication all
// run on the same canonical routes, without registering or retaining aliases.
type Router struct {
	*gin.Engine
	AdminPaths  *Service
	publicPages []string
}

func Wrap(engine *gin.Engine, s *Service, publicPages []string) *Router {
	s.Configure(engine.Routes, publicPages)
	return &Router{Engine: engine, AdminPaths: s, publicPages: publicPages}
}
func Path(req *http.Request) string {
	if state, ok := req.Context().Value(requestKey{}).(requestState); ok {
		return state.Path
	}
	return Default // Standalone server-side rendering/tests, never a client fallback.
}
func OriginalPath(req *http.Request) string {
	if state, ok := req.Context().Value(requestKey{}).(requestState); ok {
		return state.Original
	}
	return req.URL.Path
}
func prefix(path, base string) bool { return path == base || strings.HasPrefix(path, base+"/") }
func (r *Router) public(path string) bool {
	// Public namespaces cannot be selected as the management root. Requests to
	// their existing routes do not depend on management configuration or reads.
	for _, route := range r.Engine.Routes() {
		if prefix(route.Path, CanonicalAPI) {
			continue
		}
		root := strings.Split(strings.TrimPrefix(route.Path, "/"), "/")[0]
		if root != "api" && root != "" && root[0] != ':' && prefix(path, "/"+root) {
			return true
		}
		if strings.HasPrefix(route.Path, "/api/v1/") {
			parts := strings.Split(strings.TrimPrefix(route.Path, "/api/v1/"), "/")
			if len(parts) > 0 && parts[0] != "admin" && parts[0] != "" && prefix(path, "/api/v1/"+parts[0]) {
				return true
			}
		}
	}
	for _, page := range r.publicPages {
		root := strings.Split(strings.TrimPrefix(page, "/"), "/")[0]
		if root != "" && root[0] != ':' && prefix(path, "/"+root) {
			return true
		}
	}
	return path == "/"
}
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	current := ""
	if !r.public(req.URL.Path) {
		var err error
		current, err = r.AdminPaths.Current(req.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusInternalServerError)
			if req.Method != http.MethodHead {
				_ = json.NewEncoder(w).Encode(gin.H{"code": "INTERNAL_ERROR", "message": "服务器内部错误", "data": nil, "signature": nil})
			}
			return
		}
	}
	external := req.URL.Path
	internal := external
	missing := false
	if current != "" {
		api := "/api/v1" + current
		switch {
		case prefix(external, api):
			internal = CanonicalAPI + strings.TrimPrefix(external, api)
		case prefix(external, current):
			internal = Default + strings.TrimPrefix(external, current)
		case current != Default && (prefix(external, Default) || prefix(external, CanonicalAPI)):
			// Route through the ordinary NoRoute pipeline, including global body limits.
			// The underscore cannot be a configured management segment. This is not a
			// registered endpoint, redirect or special externally distinguishable 404.
			internal = "/__authgo_unmatched_route__"
			missing = true
		}
	}
	copy := req.Clone(context.WithValue(req.Context(), requestKey{}, requestState{Path: current, Original: external, Missing: missing}))
	if internal != external {
		url := *copy.URL
		url.Path = internal
		url.RawPath = ""
		copy.URL = &url
	}
	r.Engine.ServeHTTP(w, copy)
}

// Routes returns the actual externally reachable management paths for contract
// checks; canonical private routes are never advertised as an old alias.
func (r *Router) Routes() gin.RoutesInfo {
	current, err := r.AdminPaths.Current(context.Background())
	if err != nil {
		return nil
	}
	routes := append(gin.RoutesInfo(nil), r.Engine.Routes()...)
	for i := range routes {
		if prefix(routes[i].Path, CanonicalAPI) {
			routes[i].Path = "/api/v1" + current + strings.TrimPrefix(routes[i].Path, CanonicalAPI)
		}
	}
	return routes
}

// MissingGuard runs after universal safety/body-limit middleware but before
// authentication and dispatch. Even a future route/static file matching the
// internal sentinel can never turn a retired management URL into an alias.
func MissingGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		state, _ := c.Request.Context().Value(requestKey{}).(requestState)
		if state.Missing {
			response.NotFound(c)
			return
		}
		c.Next()
	}
}
