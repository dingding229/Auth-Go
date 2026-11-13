// Package crypto contains application cryptography, independent of administrator
// JWT/TOTP encryption so existing auth keys and ciphertext formats stay unchanged.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

type Cipher struct{ aead cipher.AEAD }

func NewCipher(master []byte) (*Cipher, error) {
	if len(master) != 32 {
		return nil, errors.New("主密钥必须为 32 字节")
	}
	key, err := hkdf.Key(sha256.New, master, nil, "authgo/application/encryption/v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead}, nil
}
func (c *Cipher) Encrypt(plaintext, aad []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "v1:" + base64.RawStdEncoding.EncodeToString(c.aead.Seal(nonce, nonce, plaintext, aad)), nil
}
func (c *Cipher) Decrypt(encrypted string, aad []byte) ([]byte, error) {
	if len(encrypted) < 3 || encrypted[:3] != "v1:" {
		return nil, errors.New("密文版本无效")
	}
	payload, err := base64.RawStdEncoding.DecodeString(encrypted[3:])
	if err != nil || len(payload) < c.aead.NonceSize()+c.aead.Overhead() {
		return nil, errors.New("密文格式无效")
	}
	n := c.aead.NonceSize()
	plain, err := c.aead.Open(nil, payload[:n], payload[n:], aad)
	if err != nil {
		return nil, errors.New("密文校验失败")
	}
	return plain, nil
}
func RandomString(bytes int) (string, error) {
	if bytes < 1 || bytes > 4096 {
		return "", errors.New("随机数据长度无效")
	}
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
func Sign(private ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("Ed25519 私钥长度无效")
	}
	if !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) {
		return nil, errors.New("Ed25519 私钥内容无效")
	}
	return ed25519.Sign(private, message), nil
}
func Verify(public ed25519.PublicKey, message, signature []byte) bool {
	return len(public) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && ed25519.Verify(public, message, signature)
}
func PublicKeyPEM(public ed25519.PublicKey) ([]byte, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, errors.New("Ed25519 公钥长度无效")
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("公钥 PEM 格式无效")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("公钥内容无效")
	}
	key, ok := public.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("公钥不是 Ed25519 类型")
	}
	return key, nil
}
func SHA256(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func HMACSHA256(key, message []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}
func VerifyHMACSHA256(key, message []byte, signature string) bool {
	if len(signature) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return hmac.Equal(decoded, mac.Sum(nil))
}
