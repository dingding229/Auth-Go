//go:build linux

package sdk

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestProtectedMemfdSealsAndBoundedPlaintext(t *testing.T) {
	raw, key := protectedFixture(t, []byte("never write this on a persistent disk"))
	image, e := ReadProtectedImage(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	fd, e := prepareProtected(image, key)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	got, e := io.ReadAll(fd)
	if e != nil || !bytes.Equal(got, protectedExpected([]byte("never write this on a persistent disk"))) {
		t.Fatal(e)
	}
	path, e := os.Readlink("/proc/self/fd/" + fmtFD(fd))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(path, "memfd:") {
		flags, _, err := syscall.Syscall(syscall.SYS_FCNTL, fd.Fd(), 1034, 0)
		if err != 0 || flags&15 != 15 {
			t.Fatal("unsealed memfd")
		}
	} else {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(fd.Fd()), &fs) != nil || uint64(fs.Type) != tmpfsMagic || !strings.Contains(path, "(deleted)") {
			t.Fatal("persistent/named plaintext file")
		}
	}
}
func fmtFD(fd *os.File) string { return fmt.Sprint(fd.Fd()) }
func TestProtectedDumpableGuardMarker(t *testing.T) {
	before, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 3, 0, 0)
	if e != 0 {
		t.Fatal(e)
	}
	defer syscall.RawSyscall(syscall.SYS_PRCTL, 4, before, 0)
	t.Setenv("AUTHGO_PROTECTED", "1")
	hardenProtected()
	got, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 3, 0, 0)
	if e != 0 || got != 0 {
		t.Fatal("protected process is dumpable", got, e)
	}
}

func TestProtectedFailureDiagnosticsDoNotEchoRemoteText(t *testing.T) {
	for _, code := range []string{TrialDisabled, LicenseRevoked, FloatingLimitReached, PayloadInvalid, "REMOTE_" + testKey} {
		err := failure(code, testKey+" secret server-controlled message", nil)
		if strings.Contains(protectedReason(err), testKey) || strings.Contains(protectedErrorCode(err), testKey) {
			t.Fatal("remote text leaked")
		}
	}
	if !strings.Contains(protectedReason(failure(TrialDisabled, "", nil)), "AUTHGO_LICENSE") {
		t.Fatal("missing license instruction")
	}
	if protectedFallbackAllowed(&authenticatedServerError{original: failure(LicenseRevoked, "", nil)}) {
		t.Fatal("refusal fallback")
	}
	if protectedFallbackAllowed(failure(ClockRollback, "", nil)) {
		t.Fatal("clock rollback fallback")
	}
}
