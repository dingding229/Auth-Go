package portal

import (
	"encoding/json"
	"strings"
)

// Called at router assembly, using the embedded Docker integration specification.
// portal cannot import apidocs because that package references portal DTOs.
func (s *Service) SetDeploymentGuide(raw string) {
	_, body, ok := strings.Cut(raw, "## 给客户：运行与排查（可单独转发）")
	if ok {
		s.deploymentGuide = strings.TrimSpace(body)
	}
}
func yamlString(raw string) string {
	b, _ := json.Marshal(strings.ReplaceAll(raw, "$", "$$"))
	return string(b)
}
func (s *Service) deployment(card UserLicense, choice versionChoice, isUsable bool) Deployment {
	out := Deployment{DockerImage: choice.image, Tag: choice.tag, DockerPull: choice.pull, Steps: []string{"docker compose pull", "docker compose up -d", "docker compose logs --tail=50"}, Guide: s.deploymentGuide, PortsHint: "如程序需要对外提供服务，请按软件文档添加 ports"}
	switch {
	case !isUsable:
		out.Reason = "授权当前不可运行，请联系软件提供方"
	case choice.image == "":
		out.Reason = "软件未配置 Docker 镜像，请联系软件提供方"
	case choice.tag == "":
		out.Reason = "暂无授权范围内的可用镜像版本，请联系软件提供方"
	default:
		out.Available = true
		// Only this ownership-checked detail response contains a ready-to-run secret.
		// Keep the published image's own non-root USER; never override it with root.
		out.Compose = "services:\n  app:\n    image: " + yamlString(choice.image+":"+choice.tag) + "\n    restart: unless-stopped\n    environment:\n      AUTHGO_LICENSE: " + yamlString(card.Key) + "\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    stop_grace_period: 10s\n    volumes:\n      - authgo_cache:/var/lib/authgo\nvolumes:\n  authgo_cache:\n"
	}
	return out
}
