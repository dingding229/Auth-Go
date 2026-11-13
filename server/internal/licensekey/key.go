// Package licensekey generates typo-checkable, cryptographically random codes.
// The check character is public error detection, never an authentication MAC.
package licensekey

import (
	"crypto/rand"
	"errors"
	"strings"
)

const Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
const DefaultPrefix = "AUTH"

func Prefix(prefix string) (string, error) {
	if prefix == "" {
		prefix = DefaultPrefix
	}
	prefix = strings.ToUpper(strings.TrimSpace(prefix))
	if len(prefix) < 1 || len(prefix) > 16 {
		return "", errors.New("授权码前缀须为 1 至 16 位")
	}
	for _, c := range prefix {
		if !strings.ContainsRune(Alphabet, c) {
			return "", errors.New("授权码前缀仅允许大写字母和数字，排除 0/O/1/I")
		}
	}
	return prefix, nil
}
func checksum(prefix, data string) byte {
	value := len(prefix) % 32
	for _, c := range prefix + data {
		value = (value*17 + strings.IndexRune(Alphabet, c)) % 32
	}
	return Alphabet[value]
}
func Generate(prefix string) (string, error) {
	prefix, err := Prefix(prefix)
	if err != nil {
		return "", err
	}
	random := make([]byte, 19)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for i := range random {
		random[i] = Alphabet[random[i]&31]
	}
	data := string(random)
	last := data[15:] + string(checksum(prefix, data))
	return prefix + "-" + data[:5] + "-" + data[5:10] + "-" + data[10:15] + "-" + last, nil
}
func Validate(key string) error {
	if len(key) < 25 || len(key) > 40 {
		return errors.New("授权码长度无效")
	}
	parts := strings.Split(key, "-")
	if len(parts) != 5 {
		return errors.New("授权码格式无效")
	}
	prefix, err := Prefix(parts[0])
	if err != nil || prefix != parts[0] {
		return errors.New("授权码前缀无效")
	}
	for _, part := range parts[1:] {
		if len(part) != 5 {
			return errors.New("授权码分组长度无效")
		}
		for _, c := range part {
			if !strings.ContainsRune(Alphabet, c) {
				return errors.New("授权码字符无效")
			}
		}
	}
	data := parts[1] + parts[2] + parts[3] + parts[4][:4]
	if parts[4][4] != checksum(prefix, data) {
		return errors.New("授权码校验位无效")
	}
	return nil
}
