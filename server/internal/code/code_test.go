package code

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

// Discover production constants instead of maintaining a second error-code list.
// Check the map directly: Describe's internal-error fallback must not hide omissions.
func TestEveryErrorCodeConstantHasDescription(t *testing.T) {
	fset := token.NewFileSet()
	packages, err := parser.ParseDir(fset, ".", func(info os.FileInfo) bool { return !strings.HasSuffix(info.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	source, ok := packages["code"]
	if !ok {
		t.Fatal("error code package not found")
	}
	files := make([]*ast.File, 0, len(source.Files))
	for _, file := range source.Files {
		files = append(files, file)
	}
	config := types.Config{Importer: importer.Default()}
	pkg, err := config.Check("authgo/internal/code", fset, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range pkg.Scope().Names() {
		c, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok || c.Val().Kind() != constant.String {
			continue
		}
		count++
		value := constant.StringVal(c.Val())
		t.Run(name, func(t *testing.T) {
			d, ok := descriptions[value]
			if !ok {
				t.Fatalf("error code %s (%q) has no description", name, value)
			}
			if strings.TrimSpace(d.Message) == "" {
				t.Fatalf("error code %s has an empty message", name)
			}
			if value == OK {
				if d.Status != 200 {
					t.Fatalf("OK status = %d, want 200", d.Status)
				}
			} else if d.Status < 400 || d.Status > 599 {
				t.Fatalf("error code %s has invalid HTTP status %d", name, d.Status)
			}
			if Describe(value) != d {
				t.Fatalf("Describe(%q) did not return its registered description", value)
			}
		})
	}
	if count == 0 {
		t.Fatal("no error-code constants discovered")
	}
}

func TestCustomerErrorDescriptions(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
	}{
		{VersionNotAllowed, 403}, {DeviceInvalid, 400},

		{FloatingLimitReached, 403}, {LeaseExpired, 403},
	} {
		t.Run(tc.code, func(t *testing.T) {
			d := Describe(tc.code)
			if d.Status != tc.status || d.Message == Describe(InternalError).Message {
				t.Fatalf("Describe(%q) = %+v, want customer message and status %d", tc.code, d, tc.status)
			}
		})
	}
	if d := Describe(FloatingLimitReached); d.Message != "运行实例数已达授权上限，请停止其他实例或联系提供方" {
		t.Fatal(d)
	}

}

func TestUnknownCodeStillFallsBackToInternalError(t *testing.T) {
	if got := Describe("UNKNOWN_UNREGISTERED_CODE"); got != descriptions[InternalError] {
		t.Fatal(got)
	}
}
