package apidocs

import (
	"strings"
	"testing"
)

func TestEmbeddedProtocolDocument(t *testing.T) {
	for _, section := range []string{
		"# Auth Go 客户端协议 v2",
		"## 1. 基础编码与配置",
		"## 4. 故障状态机",
		"## 12. 语言无关加密载荷",
	} {
		if !strings.Contains(Protocol, section) {
			t.Fatalf("嵌入协议缺少关键章节: %s", section)
		}
	}
	assertNoRelativeRepositoryLinks(t, "Protocol", Protocol)
}

func TestEmbeddedDockerDocument(t *testing.T) {
	for _, section := range []string{
		"# Docker接入与部署",
		"## 给开发者：五步接入",
		"## 给客户：运行与排查（可单独转发）",
	} {
		if !strings.Contains(Docker, section) {
			t.Fatalf("嵌入Docker说明缺少关键章节: %s", section)
		}
	}
	assertNoRelativeRepositoryLinks(t, "Docker", Docker)
}

func assertNoRelativeRepositoryLinks(t *testing.T, name, text string) {
	t.Helper()
	for _, marker := range []string{
		"](../", "](README", "](sdk/", "] (../", "] (README", "] (sdk/",
	} {
		if strings.Contains(text, marker) {
			t.Fatalf("嵌入%s文档含仓库相对链接: %s", name, marker)
		}
	}
}
