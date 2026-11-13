package mailer

import (
	"context"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestChineseTemplatesAndValidation(t *testing.T) {
	message := Expiring("测试站点", "应用", "AUTH-***", 3, time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), "user@example.com")
	if !strings.Contains(message.Subject, "授权到期提醒") || !strings.Contains(message.Body, "3 天") || !strings.Contains(message.Body, "UTC") {
		t.Fatal(message)
	}
	code, e := PortalCode("站点", "user@example.com", "123456", time.Now().Add(time.Minute))
	if e != nil || !strings.Contains(code.Body, "123456") {
		t.Fatal(code, e)
	}
	if _, e := PortalCode("站点", "u@example.com", "12345x", time.Now()); e == nil {
		t.Fatal("bad code")
	}
	for _, address := range []string{"bad", "a@example.com\r\nBcc:other@example.com", "中文@example.com"} {
		if _, e := Address(address); e == nil {
			t.Fatal(address)
		}
	}
	if e := Validate(Config{Enabled: true, Host: "smtp.example.com", Port: 25, Mode: "plain", From: "a@example.com"}); e == nil {
		t.Fatal("remote plaintext SMTP permitted")
	}
}
func TestSMTPWireAndRequiredSTARTTLS(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	messages := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		tp := textproto.NewConn(conn)
		_ = tp.PrintfLine("220 localhost test")
		for {
			line, e := tp.ReadLine()
			if e != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				_ = tp.PrintfLine("250-localhost\r\n250 AUTH PLAIN")
			case strings.HasPrefix(line, "AUTH"):
				_ = tp.PrintfLine("235 authenticated")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				_ = tp.PrintfLine("250 ok")
			case line == "DATA":
				_ = tp.PrintfLine("354 send")
				raw, e := tp.ReadDotBytes()
				if e != nil {
					return
				}
				messages <- string(raw)
				_ = tp.PrintfLine("250 accepted")
			case line == "QUIT":
				_ = tp.PrintfLine("221 bye")
				return
			default:
				_ = tp.PrintfLine("500 unsupported")
			}
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	cfg := Config{Enabled: true, Host: "127.0.0.1", Port: port, From: "sender@example.com", Username: "user", Password: "secret", Mode: "plain"}
	if e := Send(context.Background(), cfg, Message{To: "receiver@example.com", Subject: "中文主题", Body: "正文\n.点开头"}); e != nil {
		t.Fatal(e)
	}
	raw := <-messages
	if !strings.Contains(raw, "Content-Type: text/plain; charset=UTF-8") || !strings.Contains(raw, "=?UTF-8?q?") || !strings.Contains(raw, ".点开头") {
		t.Fatal(raw)
	}
	<-done
	// A non-TLS server may not silently downgrade a required STARTTLS mode.
	insecure, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer insecure.Close()
	go func() {
		conn, e := insecure.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		tp := textproto.NewConn(conn)
		tp.PrintfLine("220 localhost")
		tp.ReadLine()
		tp.PrintfLine("250 localhost")
		tp.ReadLine()
	}()
	cfg.Port = insecure.Addr().(*net.TCPAddr).Port
	cfg.Mode = "starttls"
	if e := Send(context.Background(), cfg, Message{To: "receiver@example.com", Subject: "测试", Body: strconv.Itoa(1)}); e == nil {
		t.Fatal("STARTTLS downgrade accepted")
	}
}
