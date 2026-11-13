package sdk

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Injectable reads keep host/container detection testable without consulting hardware.
func detectContainer(read func(string) ([]byte, error), env func(string) string) bool {
	switch env("AUTHGO_CONTAINER") {
	case "0":
		return false
	case "1":
		return true
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := read(path); err == nil {
			return true
		}
	}
	data, _ := read("/proc/1/cgroup")
	for _, name := range []string{"docker", "containerd", "kubepods", "libpod"} {
		if strings.Contains(string(data), name) {
			return true
		}
	}
	return false
}

func instanceFingerprint(id string) string { return sha([]byte("authgo/instance/v1\x00" + id)) }

var memoryInstances sync.Map

func containerIdentity(dir string) (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	candidate := hex.EncodeToString(random[:])
	read := func(path string) (string, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 64 {
			return "", errors.New("invalid instance identity file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if !validFingerprint(string(raw)) || string(raw) != strings.ToLower(string(raw)) {
			return "", errors.New("invalid instance identity")
		}
		return string(raw), nil
	}
	persist := func() (string, error) {
		if dir == "" {
			return "", errors.New("cache disabled")
		}
		path := filepath.Join(dir, "instance-id")
		if id, err := read(path); err == nil {
			return id, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", err
		}
		file, err := os.CreateTemp(dir, ".instance-*")
		if err != nil {
			return "", err
		}
		defer os.Remove(file.Name())
		if _, err = file.WriteString(candidate); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		// link publishes the complete 0600 file atomically; concurrent losers
		// never see a partially written ID and read the winner instead.
		if err = os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		return read(path)
	}
	id, err := persist()
	if err == nil {
		return id, nil
	}
	key, absErr := filepath.Abs(dir)
	if absErr != nil {
		key = dir
	}
	actual, _ := memoryInstances.LoadOrStore(key, candidate)
	return actual.(string), err
}
