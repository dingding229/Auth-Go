//go:build linux

package sdk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const tmpfsMagic = 0x01021994

func disableDumpable() error {
	_, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 4, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
func hardenProtected() {
	if os.Getenv("AUTHGO_PROTECTED") == "1" {
		if disableDumpable() != nil {
			log.Print("受保护进程无法禁用转储，继续运行；请检查容器安全策略")
		}
	}
}

// RunProtected is the Linux launcher's high-level entry point. Configuration is
// read exclusively from the executable's authenticated tail, never environment.
// It does not start an authorization loop or release the seat before exec.
func RunProtected(args, environment []string, stderr io.Writer) int {
	self, e := os.Open("/proc/self/exe")
	if e != nil {
		fmt.Fprintln(stderr, "无法读取受保护程序")
		return ExitLicense
	}
	defer self.Close()
	st, e := self.Stat()
	if e != nil {
		fmt.Fprintln(stderr, "无法读取受保护程序")
		return ExitLicense
	}
	image, e := ReadProtectedImage(self, st.Size())
	if e != nil {
		fmt.Fprintln(stderr, "受保护程序尾部结构无效")
		return ExitLicense
	}
	files, _ := image.Payload.Files()
	if files[image.Index].Architecture != runtime.GOARCH || len(args) == 0 {
		fmt.Fprintln(stderr, "受保护程序架构或启动参数不匹配")
		return ExitLicense
	}
	if disableDumpable() != nil {
		fmt.Fprintln(stderr, "无法禁用进程转储，继续运行；宿主机root仍可读取程序内存")
	}
	client, e := New(image.Payload.Config, WithClientVersion(image.Payload.Version))
	if e != nil {
		fmt.Fprintln(stderr, "受保护程序的编译接入配置无效")
		return ExitLicense
	}
	client.stubMode = true
	license := os.Getenv("AUTHGO_LICENSE")
	_, e = client.guardCheck(context.Background(), license)
	var key []byte
	if e == nil {
		key, e = client.unlockPayloadMaterial(context.Background(), image.Payload)
	}
	if e != nil && protectedFallbackAllowed(e) {
		key, e = client.protectedCachedKey(image.Payload)
	}
	if e != nil {
		fmt.Fprintf(stderr, "%s（%s）\n", protectedReason(e), protectedErrorCode(e))
		return ExitLicense
	}
	// Explicit clear before Exec: defers do not run after successful replacement.
	prepared, e := prepareProtected(image, key)
	clear(key)
	if e != nil {
		fmt.Fprintln(stderr, "受保护程序解密失败或没有可执行的内存文件系统，请检查memfd、tmpfs及容器安全策略")
		return ExitLicense
	}
	defer prepared.Close()
	env := make([]string, 0, len(environment)+1)
	for _, v := range environment {
		if !strings.HasPrefix(v, "AUTHGO_PROTECTED=") {
			env = append(env, v)
		}
	}
	env = append(env, "AUTHGO_PROTECTED=1")
	exec := func(f *os.File) error { return syscall.Exec(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), args, env) }
	e = exec(prepared)
	// Executability is decided by the kernel at exec time (including seccomp,
	// vm.memfd_noexec and LSM policy). The already-verified bytes may be copied
	// only to an executable tmpfs, never to a persistent filesystem.
	if e != nil {
		fallback, err := tmpfsExecutable(func(w io.Writer) error {
			_, err := io.Copy(w, io.NewSectionReader(prepared, 0, files[image.Index].Size))
			return err
		})
		if err == nil {
			defer fallback.Close()
			e = exec(fallback)
		}
	}
	fmt.Fprintln(stderr, "无法执行受保护程序：memfd和tmpfs均不可执行，或镜像缺少动态解释器及库")
	return ExitLicense
}
func protectedErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case LicenseExpired, LicenseRevoked, LicenseSuspended, LicenseNotStarted, LicenseNotFound, LicenseNotActivated, UserDisabled, AppDisabled, ActivationInvalid, InstanceReplaced, FloatingLimitReached, LeaseExpired, VersionDisabled, VersionNotAllowed, MaintenanceExpired, TrialDisabled, TrialIPLimit, TrialQuotaExceeded, PayloadInvalid, RateLimited, NetworkError, GraceExpired, CacheUnavailable, CacheInvalid, InvalidConfig, ResponseSignatureInvalid, ResponseInvalid, ClockRollback:
			return e.Code
		}
	}
	return ResponseInvalid
}
func prepareProtected(image ProtectedImage, key []byte) (*os.File, error) {
	file, e := newProtectedMemfd()
	if e == nil {
		if e = image.Decrypt(file, key); e != nil {
			file.Close()
			return nil, e
		}
		if e = file.Chmod(0500); e == nil {
			_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), 1033, 15)
			if errno != 0 {
				e = errno
			}
		}
		if e == nil {
			ro, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
			file.Close()
			if err == nil {
				return ro, nil
			}
			return nil, err
		}
		file.Close()
	}
	return tmpfsExecutable(func(w io.Writer) error { return image.Decrypt(w, key) })
}
func newProtectedMemfd() (*os.File, error) {
	if protectedMemfdSyscall == 0 {
		return nil, syscall.ENOSYS
	}
	name, e := syscall.BytePtrFromString("authgo-main")
	if e != nil {
		return nil, e
	}
	for _, flags := range []uintptr{0x13, 0x03} {
		fd, _, errno := syscall.Syscall(protectedMemfdSyscall, uintptr(unsafe.Pointer(name)), flags, 0)
		if errno == 0 {
			return os.NewFile(fd, "memfd:authgo-main"), nil
		}
		if errno != syscall.EINVAL {
			return nil, errno
		}
	}
	return nil, syscall.ENOSYS
}

// All writes are through a directory FD already verified as tmpfs. No named
// plaintext remains: open read-only, close the writable handle, unlink, exec FD.
func tmpfsExecutable(write func(io.Writer) error) (*os.File, error) {
	for _, directory := range []string{"/dev/shm", "/tmp"} {
		dir, e := os.Open(directory)
		if e != nil {
			continue
		}
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(dir.Fd()), &fs) != nil || uint64(fs.Type) != tmpfsMagic || fs.Flags&syscall.MS_NOEXEC != 0 {
			dir.Close()
			continue
		}
		random, e := wireRandomName()
		if e != nil {
			dir.Close()
			return nil, e
		}
		name := ".authgo-exec-" + random
		fd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			dir.Close()
			continue
		}
		f := os.NewFile(uintptr(fd), filepath.Join(directory, name))
		cleanup := func() { f.Close(); _ = syscall.Unlinkat(int(dir.Fd()), name); dir.Close() }
		var actual syscall.Statfs_t
		if syscall.Fstatfs(fd, &actual) != nil || uint64(actual.Type) != tmpfsMagic {
			cleanup()
			continue
		}
		if e = write(f); e != nil {
			cleanup()
			return nil, e
		}
		if e = f.Chmod(0500); e == nil {
			e = f.Sync()
		}
		if e != nil {
			cleanup()
			continue
		}
		rofd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if e != nil {
			cleanup()
			continue
		}
		ro := os.NewFile(uintptr(rofd), "unlinked-authgo-tmpfs")
		if e = syscall.Unlinkat(int(dir.Fd()), name); e != nil {
			ro.Close()
			cleanup()
			continue
		}
		f.Close()
		dir.Close()
		return ro, nil
	}
	return nil, errors.New("没有可执行的tmpfs")
}

func wireRandomName() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}

func protectedFallbackAllowed(e error) bool {
	var watermark *payloadWatermarkError
	if errors.As(e, &watermark) {
		return false
	}
	if explicitRefusal(e) {
		return false
	}
	var detail *Error
	if errors.As(e, &detail) {
		switch detail.Code {
		case InvalidConfig, InvalidLicenseKey, ClockRollback, InstanceReplaced:
			return false
		}
	}
	return true
}

func protectedReason(err error) string {
	switch protectedErrorCode(err) {
	case TrialDisabled:
		return "试用未开启，请设置AUTHGO_LICENSE"
	case TrialIPLimit:
		return "当前网络已领取试用，请设置正式AUTHGO_LICENSE"
	case TrialQuotaExceeded:
		return "今日试用名额已满，请稍后重试或设置AUTHGO_LICENSE"
	case LicenseExpired:
		return "授权已到期，请联系提供方续期"
	case LicenseRevoked:
		return "授权已吊销"
	case LicenseSuspended:
		return "授权已暂停"
	case FloatingLimitReached:
		return "运行实例数已达授权上限，请停止其他实例或联系提供方"
	case MaintenanceExpired:
		return "当前授权的更新维护期已结束，此版本需要续期"
	case VersionDisabled:
		return "此版本已停用，请使用可用版本"
	case PayloadInvalid:
		return "加密载荷无效，无法解锁程序"
	case GraceExpired:
		return "启动授权证据的宽限期已结束，请恢复联网"
	case CacheInvalid, CacheUnavailable:
		return "启动授权证据或密钥缓存缺失、过期或无效，无法离线启动"
	case NetworkError:
		return "无法连接授权服务器，且没有可用的离线密钥缓存"
	default:
		return "无法验证授权或取得内容密钥，请检查网络与授权设置"
	}
}
