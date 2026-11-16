package backupfile

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const encryptedMagic = "AUTHGO-BACKUP\x00\x00\x00"
const headerSize = 62
const chunkSize = 1 << 20
const memoryKiB = 64 * 1024
const iterations = 3
const parallelism = 2

var ErrPasswordRequired = errors.New("备份已加密，请输入备份密码")
var errEncryptedBackup = errors.New("备份密码错误或文件已损坏（被篡改或截断）")

func ValidatePassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 4096 {
		return errors.New("备份密码至少需要 12 个字符，且不能超过 4096 字节")
	}
	return nil
}

func IsEncrypted(r io.ReaderAt) (bool, error) {
	prefix := make([]byte, len(encryptedMagic))
	n, err := r.ReadAt(prefix, 0)
	if err != nil && err != io.EOF {
		return false, err
	}
	return n == len(prefix) && string(prefix) == encryptedMagic, nil
}

func EncryptedSize(size int64) (int64, error) {
	if size < 0 {
		return 0, errors.New("备份大小无效")
	}
	blocks := size / chunkSize
	if size%chunkSize != 0 {
		blocks++
	}
	overhead := int64(headerSize) + (blocks+1)*20
	if size > math.MaxInt64-overhead {
		return 0, errors.New("备份过大")
	}
	return size + overhead, nil
}

func writeBytes(dst io.Writer, data []byte) error {
	n, err := dst.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

// Version 1: magic[16], version[1], salt[16], Argon2 memory/time/lanes[4/4/1],
// chunk size[4], nonce prefix[16]. Each record has U32 length then ciphertext/tag;
// an authenticated empty record terminates the stream. All integers are big-endian.
func Encrypt(dst io.Writer, src io.Reader, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	header := make([]byte, headerSize)
	copy(header, encryptedMagic)
	header[16] = 1
	if _, err := rand.Read(header[17:33]); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header[33:37], memoryKiB)
	binary.BigEndian.PutUint32(header[37:41], iterations)
	header[41] = parallelism
	binary.BigEndian.PutUint32(header[42:46], chunkSize)
	if _, err := rand.Read(header[46:62]); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(password), header[17:33], iterations, memoryKiB, parallelism, 32)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	if err = writeBytes(dst, header); err != nil {
		return err
	}
	plain := make([]byte, chunkSize)
	defer clear(plain)
	for index := uint64(0); ; index++ {
		n, readErr := io.ReadFull(src, plain)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		nonce, aad := recordContext(header, index, uint32(n))
		sealed := aead.Seal(nil, nonce, plain[:n], aad)
		if err = writeBytes(dst, aad[len(aad)-4:]); err != nil {
			return err
		}
		if err = writeBytes(dst, sealed); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

func recordContext(header []byte, index uint64, size uint32) ([]byte, []byte) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(nonce, header[46:62])
	binary.BigEndian.PutUint64(nonce[16:], index)
	aad := make([]byte, headerSize+12)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[headerSize:], index)
	binary.BigEndian.PutUint32(aad[headerSize+8:], size)
	return nonce, aad
}

// Decrypt writes authenticated chunks only. Callers must stage output and publish
// it only after the authenticated terminator and physical EOF have been checked.
func Decrypt(dst io.Writer, src io.Reader, password string) error {
	if password == "" {
		return ErrPasswordRequired
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return errEncryptedBackup
	}
	// Reject unsupported parameters before Argon2 allocation; tampered headers
	// cannot request unbounded memory or CPU. Version 1 uses one fixed profile.
	if string(header[:16]) != encryptedMagic || header[16] != 1 ||
		binary.BigEndian.Uint32(header[33:37]) != memoryKiB ||
		binary.BigEndian.Uint32(header[37:41]) != iterations || header[41] != parallelism ||
		binary.BigEndian.Uint32(header[42:46]) != chunkSize {
		return errEncryptedBackup
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(password), header[17:33], iterations, memoryKiB, parallelism, 32)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	buffer := make([]byte, chunkSize+aead.Overhead())
	defer clear(buffer)
	for index := uint64(0); ; index++ {
		var length [4]byte
		if _, err = io.ReadFull(src, length[:]); err != nil {
			return errEncryptedBackup
		}
		n := binary.BigEndian.Uint32(length[:])
		if n > chunkSize {
			return errEncryptedBackup
		}
		sealed := buffer[:int(n)+aead.Overhead()]
		if _, err = io.ReadFull(src, sealed); err != nil {
			return errEncryptedBackup
		}
		nonce, aad := recordContext(header, index, n)
		plain, err := aead.Open(sealed[:0], nonce, sealed, aad)
		if err != nil {
			return errEncryptedBackup
		}
		if n == 0 {
			var extra [1]byte
			if _, err = io.ReadFull(src, extra[:]); err != io.EOF {
				return errEncryptedBackup
			}
			return nil
		}
		if err = writeBytes(dst, plain); err != nil {
			return err
		}
	}
}

// Unlock validates/decrypts an entire bundle before publishing the ZIP. Existing
// unencrypted ZIPs use the same path; no live database files are modified here.
func Unlock(source, destination, password string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	encrypted, err := IsEncrypted(in)
	if err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(destination), ".backup-unlock-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	defer out.Close()
	if encrypted {
		err = Decrypt(out, in, password)
	} else {
		var magic [4]byte
		if _, err = in.ReadAt(magic[:], 0); err != nil || !bytes.Equal(magic[:], []byte{'P', 'K', 3, 4}) {
			err = errEncryptedBackup
		}
		if err == nil {
			_, err = io.Copy(out, in)
		}
	}
	if err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	if err = validateBundle(out.Name()); err != nil {
		return err
	}
	// Do not overwrite a previous successful extraction or the original backup.
	if err = os.Link(out.Name(), destination); err != nil {
		return err
	}
	return nil
}

func validateBundle(path string) error {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return errors.New("备份 ZIP 无效或已损坏")
	}
	defer archive.Close()
	if len(archive.File) != 2 {
		return errors.New("备份 ZIP 必须只包含数据库和主密钥")
	}
	seen := map[string]bool{}
	for _, entry := range archive.File {
		if seen[entry.Name] || (entry.Name != "authgo.db" && entry.Name != "master.key") || entry.Mode()&os.ModeSymlink != 0 {
			return errors.New("备份 ZIP 成员无效")
		}
		seen[entry.Name] = true
		reader, err := entry.Open()
		if err != nil {
			return errors.New("备份 ZIP 无法读取")
		}
		if entry.Name == "master.key" {
			raw, readErr := io.ReadAll(io.LimitReader(reader, 129))
			reader.Close()
			if readErr != nil || len(raw) > 128 {
				return errors.New("备份主密钥无效")
			}
			key, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
			clear(raw)
			valid := decodeErr == nil && len(key) == 32
			clear(key)
			if !valid {
				return errors.New("备份主密钥无效")
			}
		} else {
			_, readErr := io.Copy(io.Discard, reader)
			reader.Close()
			if readErr != nil {
				return errors.New("备份数据库文件损坏")
			}
		}
	}
	return nil
}
