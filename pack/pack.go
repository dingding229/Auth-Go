package pack

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func cipherName(i int) string { return fmt.Sprintf("%08d.agc", i) }

type contentArgs []struct{ kind, value string }
type contentFlag struct {
	kind string
	args *contentArgs
}

func (f contentFlag) String() string { return "" }
func (f contentFlag) Set(s string) error {
	*f.args = append(*f.args, struct{ kind, value string }{f.kind, s})
	return nil
}

// Run is the CLI entry point. Diagnostics are deliberately fixed strings: flag
// values, configuration and cryptographic material never enter errors/logs.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "trace" {
		return runTrace(args[1:], stdout, stderr)
	}
	if e := run(args, stdout); e != nil {
		fmt.Fprintln(stderr, e.Error())
		return 1
	}
	return 0
}
func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("authgo-pack", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var public, keyID, app, version, config, protect, dest string
	var verify bool
	var contents contentArgs
	fs.StringVar(&public, "public-key", "", "")
	fs.StringVar(&keyID, "key-id", "", "")
	fs.StringVar(&app, "app-key", "", "")
	fs.StringVar(&version, "version", "", "")
	fs.StringVar(&config, "config", "", "")
	fs.StringVar(&protect, "protect", "", "")
	fs.StringVar(&dest, "out", "", "")
	fs.BoolVar(&verify, "verify", false, "")
	for _, k := range []string{"python", "node", "java", "dotnet", "php"} {
		fs.Var(contentFlag{k, &contents}, k, "")
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New("invalid command parameters")
	}
	if dest == "" {
		return errors.New("out is required")
	}
	if verify {
		if len(contents) != 0 || protect != "" || public != "" || keyID != "" || app != "" || version != "" || config != "" {
			return errors.New("verify accepts only out")
		}
		if e := Verify(dest); e != nil {
			return e
		}
		fmt.Fprintln(out, "structure verified (not authenticated)")
		return nil
	}
	pub, e := b64.DecodeString(public)
	if e != nil || len(pub) != 32 {
		return errors.New("public-key must be 32-byte base64url X25519")
	}
	if !nameRE.MatchString(keyID) || len(keyID) > 128 || app == "" || len(app) > 256 || !validVersion(version) || validateConfig(config, app) != nil {
		return errors.New("invalid metadata or pinned HTTPS config")
	}
	built := time.Now().UTC().Truncate(time.Second)
	if epoch, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		n, e := strconv.ParseInt(epoch, 10, 64)
		if e != nil || n < 0 || strconv.FormatInt(n, 10) != epoch {
			return errors.New("invalid SOURCE_DATE_EPOCH")
		}
		built = time.Unix(n, 0).UTC()
		if built.Year() > 9999 {
			return errors.New("invalid SOURCE_DATE_EPOCH")
		}
	}
	var sources []source
	for _, v := range contents {
		name, p, ok := strings.Cut(v.value, "=")
		if !ok || p == "" {
			return errors.New("content requires name=path")
		}
		s, e := inspect(v.kind, name, p)
		if e != nil {
			return e
		}
		sources = append(sources, s)
	}
	if protect != "" {
		s, e := inspect("protect", "protect", protect)
		if e != nil {
			return e
		}
		sources = append(sources, s)
	}
	if len(sources) == 0 {
		return errors.New("at least one content parameter is required")
	}
	var preparationError error
	sources, preparationError = prepareWatermarkSources(sources, pub)
	if preparationError != nil {
		return preparationError
	}
	m := Manifest{}
	for i := range sources {
		sources[i].file.Path = cipherName(i)
		m.Files = append(m.Files, sources[i].file)
	}
	p, key, e := NewPayload(Payload{V: 2, AppKey: app, Version: version, BuiltAt: built.Format("2006-01-02T15:04:05Z"), KeyID: keyID, Config: config}, m, pub)
	if e != nil {
		return errors.New("invalid payload parameters")
	}
	defer clear(key)
	if e = publish(dest, sources, p, key); e != nil {
		return e
	}
	fmt.Fprintln(out, "encrypted payload created")
	if protect != "" {
		fmt.Fprintln(out, "protected executable replaced")
	}
	return nil
}

func syncDir(p string) error {
	f, e := openSafe(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeSynced(p string, fn func(io.Writer) error) error {
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("temporary output creation failed")
	}
	e = fn(f)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return errors.New("temporary output write failed")
	}
	return nil
}

type movedInput struct {
	original, backup string
	handle           *os.File
	info             os.FileInfo
}

func inputs(sources []source) ([]entry, error) {
	var all []entry
	seen := map[string]bool{}
	for _, s := range sources {
		if s.file.Kind == "watermark" {
			continue
		}
		entries := s.entries
		if s.file.Encoding == "raw" {
			entries = []entry{{path: s.path, info: s.info}}
		}
		for _, en := range entries {
			p, e := filepath.Abs(en.path)
			if e != nil || seen[p] {
				return nil, errors.New("duplicate input path")
			}
			seen[p] = true
			en.path = p
			all = append(all, en)
		}
	}
	return all, nil
}

// publish uses a private sibling directory and same-filesystem rename. Input
// code files are renamed to rollback slots, not unlinked before publication.
// Open FDs allow restoration even if a later unlink fails during cleanup.
type publicationFS struct {
	rename func(string, string) error
	remove func(string) error
	sync   func(string) error
}

func publish(dest string, sources []source, p Payload, key []byte) error {
	return publishUsing(dest, sources, p, key, publicationFS{os.Rename, os.Remove, syncDir})
}

// The three commit operations are injectable to exercise real rollback paths.
func publishUsing(dest string, sources []source, p Payload, key []byte, fs publicationFS) (err error) {
	dest, e := filepath.Abs(dest)
	if e != nil {
		return errors.New("invalid output path")
	}
	parent := filepath.Dir(dest)
	par, e := openSafe(parent)
	if e != nil {
		return errors.New("output parent unavailable or symlink")
	}
	par.Close()
	if _, e = os.Lstat(dest); !os.IsNotExist(e) {
		return errors.New("output must not already exist")
	}
	all, e := inputs(sources)
	if e != nil {
		return e
	}
	for _, s := range sources {
		if s.file.Kind == "watermark" {
			continue
		}
		abs, _ := filepath.Abs(s.path)
		if dest == abs || strings.HasPrefix(dest, abs+string(filepath.Separator)) {
			return errors.New("output overlaps input")
		}
	}
	temp, e := os.MkdirTemp(parent, ".authgo-pack-")
	if e != nil {
		return errors.New("output staging failed")
	}
	defer os.RemoveAll(temp)
	bind, e := binding(p)
	if e != nil {
		return e
	}
	for i, s := range sources {
		e = writeSynced(filepath.Join(temp, cipherName(i)), func(w io.Writer) error {
			r, e := s.reader()
			if e != nil {
				return e
			}
			defer r.Close()
			return encrypt(w, r, s.file.Size, key, bind, uint32(i))
		})
		if e != nil {
			return e
		}
	}
	e = writeSynced(filepath.Join(temp, "payload.json"), func(w io.Writer) error { return json.NewEncoder(w).Encode(p) })
	if e != nil {
		return e
	}
	if e = syncDir(temp); e != nil {
		return errors.New("output sync failed")
	}
	var replacements []protectedReplacement
	defer func() {
		for _, v := range replacements {
			_ = os.Remove(v.temp)
		}
	}()
	for _, source := range sources {
		if source.file.Kind == "protect" {
			replacement, e := prepareProtected(source, p, temp)
			if e != nil {
				return e
			}
			replacements = append(replacements, replacement)
		}
	}
	var moved []movedInput
	published := false
	defer func() {
		if err != nil {
			failed := false
			for i := len(moved) - 1; i >= 0; i-- {
				v := moved[i]
				if _, e := os.Lstat(v.backup); e == nil {
					if os.Rename(v.backup, v.original) != nil {
						failed = true
					}
				} else {
					if _, e = v.handle.Seek(0, io.SeekStart); e != nil {
						failed = true
						continue
					}
					f, e := os.CreateTemp(filepath.Dir(v.original), ".authgo-restore-")
					if e != nil {
						failed = true
						continue
					}
					name := f.Name()
					_, e = io.Copy(f, v.handle)
					if e == nil {
						e = f.Chmod(v.info.Mode())
					}
					if e == nil {
						e = os.Chtimes(name, v.info.ModTime(), v.info.ModTime())
					}
					if e == nil {
						e = f.Sync()
					}
					f.Close()
					if e == nil {
						e = os.Rename(name, v.original)
					}
					if e != nil {
						failed = true
					}
					os.Remove(name)
				}
				if syncDir(filepath.Dir(v.original)) != nil {
					failed = true
				}
			}
			if published {
				if os.RemoveAll(dest) != nil {
					failed = true
				}
				_ = syncDir(parent)
			}
			if failed {
				err = errors.New("rollback failed; retain source filesystem and inspect .authgo-input backups")
			}
		}
		for _, v := range moved {
			v.handle.Close()
		}
	}()
	for _, en := range all {
		f, e := openSafe(en.path)
		if e != nil {
			return errors.New("input changed before commit")
		}
		st, e := f.Stat()
		if e != nil || !os.SameFile(en.info, st) || st.Size() != en.info.Size() || !st.ModTime().Equal(en.info.ModTime()) {
			f.Close()
			return errors.New("input changed before commit")
		}
		slot, e := os.CreateTemp(filepath.Dir(en.path), ".authgo-input-")
		if e != nil {
			f.Close()
			return errors.New("input staging failed")
		}
		backup := slot.Name()
		slot.Close()
		if e = fs.rename(en.path, backup); e != nil {
			os.Remove(backup)
			f.Close()
			return errors.New("input staging failed")
		}
		moved = append(moved, movedInput{en.path, backup, f, st})
		if fs.sync(filepath.Dir(en.path)) != nil {
			return errors.New("input sync failed")
		}
	}
	// Do not replace existing output, including a path created during encryption.
	if _, e = os.Lstat(dest); !os.IsNotExist(e) {
		return errors.New("output appeared during packing")
	}
	if e = fs.rename(temp, dest); e != nil {
		return errors.New("output rename failed")
	}
	published = true
	if fs.sync(parent) != nil {
		return errors.New("output sync failed")
	}
	for _, replacement := range replacements {
		if e = fs.rename(replacement.temp, replacement.original); e != nil {
			return errors.New("protected program replacement failed")
		}
		if e = fs.sync(filepath.Dir(replacement.original)); e != nil {
			return errors.New("protected program directory sync failed")
		}
	}
	for _, v := range moved {
		if fs.remove(v.backup) != nil {
			return errors.New("input cleanup failed")
		}
	}
	for _, v := range moved {
		if fs.sync(filepath.Dir(v.original)) != nil {
			return errors.New("input cleanup sync failed")
		}
	}
	return nil
}

// Verify is intentionally structural, not an authenticity or license check.
func Verify(dir string) error {
	f, e := openSafe(filepath.Join(dir, "payload.json"))
	if e != nil {
		return invalid
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 12<<20))
	if e != nil || len(b) >= 12<<20 {
		return invalid
	}
	p, e := ParsePayload(b)
	if e != nil {
		return invalid
	}
	raw, _ := b64.DecodeString(p.Manifest)
	m, _ := decodeManifestVersion(raw, p.V)
	for _, file := range m.Files {
		f, e := openSafe(filepath.Join(dir, file.Path))
		if e != nil {
			return invalid
		}
		st, e := f.Stat()
		f.Close()
		if e != nil || !st.Mode().IsRegular() || st.Size() != CipherSize(file.Size) {
			return invalid
		}
	}
	return nil
}
