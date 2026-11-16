package buildinfo

import (
	"regexp"
	"strings"
)

const PackImage = "docker.io/dingding229/authgo"
const PackImageDevelopmentNote = "开发构建没有正式版本号，打包工具使用 latest；发布时请改用固定版本或摘要。"

var releaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func PackImageTag() string {
	version := strings.TrimPrefix(Version, "v")
	if releaseVersion.MatchString(version) {
		return version
	}
	return "latest"
}
