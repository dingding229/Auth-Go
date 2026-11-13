package apidocs

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

func TestEmbeddedProtocolDocument(t *testing.T) {
	for _, section := range []string{
		"# Auth Go 客户端协议 v2", "## 1. 概览", "## 2. 编码约定",
		"## 3. 请求构造", "## 4. 加密与响应验证", "## 5. 票据与缓存",
		"## 6. 各操作说明", "## 7. 错误码与故障状态机", "## 8. 代码加密载荷格式",
		"## 9. 水印", "## 10. 测试向量", "## 11. 安全边界",
	} {
		if !strings.Contains(Protocol, section) {
			t.Fatalf("嵌入协议缺少关键章节: %s", section)
		}
	}
	// Normative domains, sizes, classification and independent vectors must not
	// disappear when the surrounding explanation or layout changes.
	for _, rule := range []string{
		"max(4096, ceil((4+L)/512)*512)", "authgo/v2/request", "authgo/v2/response",
		`authgo-gateway-v2\x00`, `authgo-ticket-v2\x00`, "RFC5869", "65536", "32768",
		"LICENSE_NOT_FOUND", "100000", "REPLAY_DETECTED", "INSTANCE_REPLACED",
		"INTERNAL_ERROR", "RATE_LIMITED", "LOG_UNAVAILABLE", "TIMESTAMP_INVALID",
		"SIGNATURE_INVALID", "INVALID_REQUEST", "PAYLOAD_INVALID", "所有未知错误码",
		"SDK_CLOCK_ROLLBACK", "SDK_GRACE_EXPIRED", "SDK_CACHE_UNAVAILABLE",
		"activate", "verify", "heartbeat", "deactivate", "release-seat", "public-key",
		"announcement", "version", "update.check", "trial", "payload.unlock",
		"4611686018427387903", "1048576", "65535", "SOURCE_DATE_EPOCH",
		`authgo-payload-envelope-v2\x00`, `authgo-payload-rewrap-v2\x00`,
		"authgo/payload/v1/wrap", "authgo/payload/v1/rewrap", `authgo-payload-chunk-v1\x00`,
		"AUTHGO-PAYLOAD-CACHE-v2.", "K32 || WM32", "AUTHGO-PAYLOAD-PROOF-v1.",
		"41555448474f2d535455422d76310000", "F_SEAL_WRITE", "TMPFS_MAGIC",
		"authgo/watermark/tag/v1", "authgo/watermark/key/v1", "__authgo_watermark",
		"SDK_INVALID_CONFIG", "TRIAL_DISABLED", "TRIAL_IP_LIMIT", "TRIAL_QUOTA_EXCEEDED",
		"v2.json", "hkdf.json", "canonical.json", "fingerprint.json", "license-key.json",
		"payload-envelope.json", "payload-unlock-v2.json", "payload-cache-v2.json", "watermark.json",
	} {
		if !strings.Contains(Protocol, rule) {
			t.Errorf("嵌入协议缺少规范规则: %s", rule)
		}
	}
	matches := regexp.MustCompile(`(?m)^## (\d+)\.`).FindAllStringSubmatch(Protocol, -1)
	if len(matches) != 11 {
		t.Fatalf("协议一级章节数量: %d", len(matches))
	}
	for i, match := range matches {
		if match[1] != fmt.Sprint(i+1) {
			t.Fatalf("协议章节编号不连续: %s", match[0])
		}
	}
}

func TestEmbeddedGuides(t *testing.T) {
	for _, document := range []struct {
		name     string
		text     string
		sections []string
	}{
		{"快速开始", Quickstart, []string{"# 快速开始", "## 1. 准备软件和授权", "## 4. 构建、发布与交付", "AUTHGO_LICENSE"}},
		{"Docker", Docker, []string{"# Docker 接入", "## 2. 接入 SDK 与授权", "GitHub Actions", "水印追查", "代码加密"}},
		{"客户", Customer, []string{"# 给客户的运行说明", "缓存卷", "反向代理与真实 IP", "X-Forwarded-For", "IPv6 ULA"}},
		{"离线与故障", Offline, []string{"# 离线与故障", "INSTANCE_REPLACED", "SDK_CLOCK_ROLLBACK", "Refused"}},
		{"协议", Protocol, []string{"# Auth Go 客户端协议 v2"}},
	} {
		t.Run(document.name, func(t *testing.T) {
			for _, section := range document.sections {
				if !strings.Contains(document.text, section) {
					t.Errorf("嵌入文档缺少关键内容: %s", section)
				}
			}
			assertNoRelativeRepositoryLinks(t, document.name, document.text)
			if regexp.MustCompile(`(?m)^#{4,} `).MatchString(document.text) {
				t.Fatal("文档标题层级超过三级")
			}
		})
	}
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

func TestGuideSizeAndCrossDocumentAnchors(t *testing.T) {
	documents := map[string]struct {
		text string
		max  int
	}{
		"quickstart": {Quickstart, 50}, "docker": {Docker, 150},
		"customer": {Customer, 60}, "offline": {Offline, 50}, "protocol": {Protocol, 400},
	}
	headings := regexp.MustCompile(`(?m)^#{1,3} (.+)$`)
	anchors := map[string]map[string]bool{}
	for name, document := range documents {
		if lines := strings.Count(document.text, "\n"); lines > document.max {
			t.Errorf("%s 文档 %d 行，超过 %d 行", name, lines, document.max)
		}
		anchors[name] = map[string]bool{}
		for _, heading := range headings.FindAllStringSubmatch(document.text, -1) {
			slug := strings.Map(func(r rune) rune {
				if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || r == '_' || r == '-' {
					return unicode.ToLower(r)
				}
				if unicode.IsSpace(r) {
					return ' '
				}
				return -1
			}, heading[1])
			anchors[name][strings.Join(strings.Fields(slug), "-")] = true
		}
	}
	links := regexp.MustCompile(`\]\(\?tab=([a-z]+)#([^\)]+)\)`)
	for name, document := range documents {
		for _, link := range links.FindAllStringSubmatch(document.text, -1) {
			if !anchors[link[1]][link[2]] {
				t.Errorf("%s 中的跨文档锚点不存在: %s", name, link[0])
			}
		}
	}
}

func TestDockerBuildExampleUsesVersionArgument(t *testing.T) {
	if !strings.Contains(Docker, "--build-arg VERSION=1.2.3") || strings.Contains(Docker, "--build-arg AUTHGO_VERSION=") {
		t.Fatal("Docker 构建示例版本参数与模板不一致")
	}
	if strings.Contains(Docker, "trace --tag <") {
		t.Fatal("追查命令包含会被 shell 解释的占位符")
	}
}
