package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestAESGCM(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	box, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range [][]byte{nil, {}, []byte("应用密钥：保密"), bytes.Repeat([]byte{0xff}, 128)} {
		aad := []byte("application:one:secret")
		sealed, err := box.Encrypt(plain, aad)
		if err != nil {
			t.Fatal(err)
		}
		second, err := box.Encrypt(plain, aad)
		if err != nil || sealed == second {
			t.Fatal("nonce reuse")
		}
		opened, err := box.Decrypt(sealed, aad)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatal("roundtrip failed", err)
		}
		restarted, _ := NewCipher(key)
		if _, err := restarted.Decrypt(sealed, aad); err != nil {
			t.Fatal("key derivation unstable")
		}
		wrong, _ := NewCipher(bytes.Repeat([]byte{8}, 32))
		if _, err := wrong.Decrypt(sealed, aad); err == nil {
			t.Fatal("wrong master accepted")
		}
		if _, err := box.Decrypt(sealed, []byte("application:two:secret")); err == nil {
			t.Fatal("wrong AAD accepted")
		}
		tampered := []byte(sealed)
		if tampered[10] == 'A' {
			tampered[10] = 'B'
		} else {
			tampered[10] = 'A'
		}
		for _, bad := range []string{"", "v2:invalid", "v1:?", "v1:AA", string(tampered), sealed[:len(sealed)-5]} {
			if _, err := box.Decrypt(bad, aad); err == nil {
				t.Fatal("invalid ciphertext accepted")
			}
		}
	}
	if _, err := NewCipher([]byte("short")); err == nil {
		t.Fatal("short master accepted")
	}
}

func TestEd25519AndPEM(t *testing.T) {
	public, private, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("待签名的授权数据")
	signature, err := Sign(private, message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(public, message, signature) || Verify(public, []byte("篡改"), signature) {
		t.Fatal("signature validation failed")
	}
	other, _, _ := GenerateEd25519()
	if Verify(other, message, signature) {
		t.Fatal("wrong public accepted")
	}
	for _, bad := range []ed25519.PrivateKey{nil, make([]byte, 63), make([]byte, 64)} {
		if _, err := Sign(bad, message); err == nil {
			t.Fatal("bad private accepted")
		}
	}
	if Verify(nil, message, signature) || Verify(public, message, nil) {
		t.Fatal("invalid key/signature accepted")
	}
	encoded, err := PublicKeyPEM(public)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicKeyPEM(encoded)
	if err != nil || !bytes.Equal(parsed, public) {
		t.Fatal("PEM roundtrip", err)
	}
	if _, err := PublicKeyPEM(nil); err == nil {
		t.Fatal("empty key exported")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	for _, bad := range [][]byte{nil, []byte("not PEM"), append(append([]byte{}, encoded...), []byte("garbage")...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})} {
		if _, err := ParsePublicKeyPEM(bad); err == nil {
			t.Fatal("invalid/non-Ed25519 PEM accepted")
		}
	}
}

func TestHMACAndRandom(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	message := []byte("Hi There")
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	if got := HMACSHA256(key, message); got != want {
		t.Fatalf("RFC 4231 vector: %s", got)
	}
	if !VerifyHMACSHA256(key, message, want) || VerifyHMACSHA256([]byte("wrong"), message, want) || VerifyHMACSHA256(key, []byte("changed"), want) {
		t.Fatal("HMAC validation failed")
	}
	for _, bad := range []string{"", "00", want[:63] + "z", want[:63] + "0"} {
		if VerifyHMACSHA256(key, message, bad) {
			t.Fatal("bad HMAC accepted")
		}
	}
	if SHA256([]byte("abc")) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("SHA256 vector")
	}
	a, err := RandomString(32)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RandomString(32)
	if len(a) != 43 || a == b {
		t.Fatal("randomness")
	}
	for _, n := range []int{0, -1, 4097} {
		if _, err := RandomString(n); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
}
