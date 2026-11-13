// Package mailer sends bounded SMTP messages and renders Chinese notification templates.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"-"`
	From     string `json:"from"`
	Mode     string `json:"mode"`
}
type Message struct{ To, Subject, Body string }

func Address(raw string) (string, error) {
	a, e := mail.ParseAddress(raw)
	if e != nil || a.Address != raw || len(raw) > 254 || strings.ContainsAny(raw, "\r\n") {
		return "", errors.New("邮箱地址无效")
	}
	for _, r := range raw {
		if r > 127 {
			return "", errors.New("邮箱必须使用 ASCII 地址")
		}
	}
	return a.Address, nil
}
func Validate(c Config) error {
	if c.Mode != "starttls" && c.Mode != "tls" && c.Mode != "plain" {
		return errors.New("SMTP 模式必须为 starttls、tls 或 plain")
	}
	if !c.Enabled {
		return nil
	}
	if c.Host == "" || len(c.Host) > 253 || (strings.ContainsAny(c.Host, "/@\r\n ") || strings.Contains(c.Host, ":") && net.ParseIP(c.Host) == nil) || c.Port < 1 || c.Port > 65535 || len(c.Username) > 254 || len(c.Password) > 1024 {
		return errors.New("SMTP 配置无效")
	}
	if _, e := Address(c.From); e != nil {
		return e
	}
	if c.Mode == "plain" {
		ip := net.ParseIP(c.Host)
		if c.Host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("明文 SMTP 仅允许回环主机")
		}
	}
	return nil
}
func Send(ctx context.Context, c Config, m Message) error {
	if !c.Enabled {
		return errors.New("SMTP 未配置")
	}
	if e := Validate(c); e != nil {
		return e
	}
	to, e := Address(m.To)
	if e != nil {
		return e
	}
	if strings.ContainsAny(m.Subject, "\r\n") || len(m.Subject) > 1024 || len(m.Body) > 64*1024 {
		return errors.New("邮件内容无效")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	address := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if c.Mode == "tls" {
		conn, e = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", address)
	} else {
		conn, e = dialer.DialContext(ctx, "tcp", address)
	}
	if e != nil {
		return errors.New("SMTP 连接失败")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	client, e := smtp.NewClient(conn, c.Host)
	if e != nil {
		return errors.New("SMTP 握手失败")
	}
	defer client.Close()
	if c.Mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP 不支持必需的 STARTTLS")
		}
		if e := client.StartTLS(&tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}); e != nil {
			return errors.New("SMTP TLS 握手失败")
		}
	}
	if c.Username != "" {
		if e := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); e != nil {
			return errors.New("SMTP 认证失败")
		}
	}
	if e := client.Mail(c.From); e != nil {
		return errors.New("SMTP 发件人被拒绝")
	}
	if e := client.Rcpt(to); e != nil {
		return errors.New("SMTP 收件人被拒绝")
	}
	writer, e := client.Data()
	if e != nil {
		return errors.New("SMTP DATA 失败")
	}
	content := "From: " + c.From + "\r\nTo: " + to + "\r\nSubject: " + mime.QEncoding.Encode("UTF-8", m.Subject) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n")
	if _, e := writer.Write([]byte(content)); e != nil {
		return errors.New("SMTP 正文发送失败")
	}
	if e := writer.Close(); e != nil {
		return errors.New("SMTP 投递失败")
	}
	_ = client.Quit()
	return nil
}
func Expiring(site, app, maskedKey string, days int, expires time.Time, to string) Message {
	return Message{To: to, Subject: "【" + site + "】授权到期提醒", Body: fmt.Sprintf("您好：\n\n您在「%s」的软件「%s」授权（%s）将在 %d 天提醒窗口内到期。\n到期时间：%s（UTC）。\n请及时联系管理员续期。\n\n如已续期，请以最新授权状态为准。", site, app, maskedKey, days, expires.UTC().Format("2006-01-02 15:04:05"))}
}
func PortalCode(site, to, code string, expires time.Time) (Message, error) {
	if len(code) != 6 {
		return Message{}, errors.New("验证码必须为6位数字")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return Message{}, errors.New("验证码必须为6位数字")
		}
	}
	return Message{To: to, Subject: "【" + site + "】用户中心登录验证码", Body: fmt.Sprintf("您的用户中心登录验证码是：%s\n有效期至 %s（UTC）。\n请勿将验证码告知他人；如非本人操作，请忽略。", code, expires.UTC().Format("2006-01-02 15:04:05"))}, nil
}
