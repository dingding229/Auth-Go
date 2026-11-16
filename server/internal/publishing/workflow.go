// Package publishing manages repository configuration and remote image builds.
package publishing

import (
	"authgo/internal/apperror"
	"authgo/internal/buildinfo"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	_ "embed"
	"regexp"
	"strings"
)

const WorkflowPath = ".github/workflows/authgo-publish.yml"

//go:embed workflow.txt
var workflowTemplate string
var imagePattern = regexp.MustCompile(`^(docker\.io/)?[a-z0-9][a-z0-9_-]*/[a-z0-9]+([._-]+[a-z0-9]+)*$`)

func directory(v Config) (string, error) {
	names := map[string]string{"Go": "go", "Python": "python", "Node.js": "node", "Rust": "rust", "Java": "java", "C#": "csharp", "PHP": "php"}
	key, ok := names[v.Language]
	if !ok || (v.Mode != "cli" && v.Mode != "fpm" && v.Mode != "apache") || (v.Language != "PHP" && v.Mode != "cli") {
		return "", apperror.Invalid("接入语言或运行方式无效")
	}
	if v.Language == "PHP" && v.Mode != "cli" {
		key += "-" + v.Mode
	}
	if v.Encrypted {
		return "examples/docker-protected/" + key, nil
	}
	if key == "go" {
		return "examples/docker", nil
	}
	return "examples/docker/" + key, nil
}
func renderWorkflow(v Config, app model.Application, key payloadkey.Key) (string, error) {
	dir, err := directory(v)
	if err != nil {
		return "", err
	}
	image := strings.TrimPrefix(app.DockerImage, "docker.io/")
	if len(image) > 255 || !imagePattern.MatchString(image) {
		return "", apperror.Invalid("请先保存有效的 Docker Hub 镜像名")
	}
	args := ""
	if v.Encrypted {
		if !regexp.MustCompile(`^[a-z0-9_-]{1,128}$`).MatchString(key.KeyID) || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(key.PublicKey) || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`).MatchString(app.AppKey) {
			return "", apperror.Invalid("请先生成当前打包公钥")
		}
		tag := buildinfo.PackImageTag()
		args = "            AUTHGO_PACK_IMAGE=" + buildinfo.PackImage + ":" + tag + "\n" + "            PAYLOAD_PUBLIC_KEY=" + key.PublicKey + "\n            PAYLOAD_KEY_ID=" + key.KeyID + "\n            PAYLOAD_APP_KEY=" + app.AppKey + "\n"
	}
	extra := ""
	if v.Language == "PHP" && v.Mode == "fpm" {
		extra = "      - name: 构建并推送 FPM nginx\n        uses: docker/build-push-action@v6\n        with:\n          context: .\n          file: " + dir + "/Dockerfile.nginx\n          push: true\n          platforms: linux/amd64,linux/arm64\n          tags: |\n            " + image + "-nginx:${{ steps.release.outputs.version }}\n            " + image + "-nginx:latest\n"
	}
	workflow := strings.NewReplacer("@DIRECTORY@", dir, "@IMAGE@", image, "@PAYLOAD_ARGS@", args, "@FPM_STEP@", extra).Replace(workflowTemplate)
	if v.Encrypted && buildinfo.PackImageTag() == "latest" {
		workflow = "# " + buildinfo.PackImageDevelopmentNote + "\n" + workflow
	}
	return workflow, nil
}
