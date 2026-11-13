package apidocs

import (
	"encoding/json"
	"strings"

	"github.com/goccy/go-yaml"
)

// Specification publishes disjoint public and authenticated management contracts.
// Unreferenced schemas are removed too, rather than leaking management-only inputs.
func Specification(management bool, managementAPI string) (map[string]any, error) {
	raw, err := Files.ReadFile("generated/swagger.json")
	if err != nil {
		return nil, err
	}
	var spec map[string]any
	if err = json.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	paths := map[string]any{}
	for path, operation := range spec["paths"].(map[string]any) {
		admin := path == "/api/v1/admin" || strings.HasPrefix(path, "/api/v1/admin/")
		if admin != management {
			continue
		}
		if admin {
			path = managementAPI + strings.TrimPrefix(path, "/api/v1/admin")
		}
		paths[path] = operation
	}
	spec["paths"] = paths
	delete(spec, "security") // Operations carry their actual explicit bearer requirements; no implicit admin default.
	info := spec["info"].(map[string]any)
	if management {
		info["title"] = "Auth Go 管理接口"
		info["description"] = "仅限已登录管理员；路径随后台地址实时更新。"
	} else {
		info["description"] = "Auth Go SDK、用户中心与健康检查接口。"
	}
	components, _ := spec["components"].(map[string]any)
	var schemas map[string]any
	if components != nil {
		schemas, _ = components["schemas"].(map[string]any)
	}
	used := map[string]bool{}
	var visit func(any)
	visit = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for key, item := range v {
				if key == "$ref" {
					ref, _ := item.(string)
					if strings.HasPrefix(ref, "#/components/schemas/") {
						name := strings.TrimPrefix(ref, "#/components/schemas/")
						if !used[name] {
							used[name] = true
							visit(schemas[name])
						}
					}
				} else {
					visit(item)
				}
			}
		case []any:
			for _, item := range v {
				visit(item)
			}
		}
	}
	visit(paths)
	kept := map[string]any{}
	for name := range used {
		if value, ok := schemas[name]; ok {
			kept[name] = value
		}
	}
	if components != nil {
		components["schemas"] = kept
		security, _ := components["securitySchemes"].(map[string]any)
		if management {
			delete(security, "PortalBearer")
		} else {
			delete(security, "AdminBearer")
		}
	}
	return spec, nil
}
func SpecificationBytes(management bool, managementAPI string, yamlFormat bool) ([]byte, error) {
	spec, err := Specification(management, managementAPI)
	if err != nil {
		return nil, err
	}
	if yamlFormat {
		return yaml.Marshal(spec)
	}
	return json.Marshal(spec)
}
