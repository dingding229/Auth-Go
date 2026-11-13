// Package integration encodes trusted developer-distributed SDK credentials.
package integration

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

type Config struct {
	URL        string `json:"url"`
	AppKey     string `json:"app_key"`
	AppSecret  string `json:"app_secret"`
	PublicKey  string `json:"public_key"`
	GatewayKey string `json:"gateway_key"`
}

func NormalizeURL(raw string) (string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Scheme != "https" && u.Scheme != "http") || u.Path != "" && u.Path != "/" {
		return "", errors.New("访问地址必须是没有用户名、查询参数或子路径的HTTP(S)地址")
	}
	u.Path = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}
func Encode(c Config) (string, error) {
	url, e := NormalizeURL(c.URL)
	if e != nil {
		return "", e
	}
	c.URL = url
	raw, e := json.Marshal(c)
	if e != nil {
		return "", errors.New("无法生成接入配置")
	}
	return "authgo2." + base64.RawURLEncoding.EncodeToString(raw), nil
}
