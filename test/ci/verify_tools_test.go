// Package ci_test holds regression tests for the CI tool guards added for
// go-auth#26: CI must use the golangci-lint, gosec and govulncheck baked into
// the ci-runner image, fail closed when one is absent or golangci-lint is not
// the pinned version, and never fall back to installing over the network.
//
// These tests run the real `make verify-lint-tool` and
// `make verify-security-tools` targets, which are what ci.yml runs, against
// fake tools on a PATH that contains nothing else. Every network-install route
// (go, curl, wget, apt-get, sudo) is on that PATH as a tripwire that records
// its invocation, so a guard that "recovers" by installing is caught.
package ci_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the module root, relative to this package directory.
const repoRoot = "../.."

// tripwires are the commands an install fallback would reach for.
var tripwires = []string{"go", "curl", "wget", "apt-get", "sudo"}

type fakeEnv struct {
	t         *testing.T
	bin       string
	tripLog   string
	toolsFile string
}

func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	dir := t.TempDir()
	f := &fakeEnv{
		t:         t,
		bin:       filepath.Join(dir, "bin"),
		tripLog:   filepath.Join(dir, "tripwire.log"),
		toolsFile: filepath.Join(dir, "ci-runner-tools.txt"),
	}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	for _, name := range tripwires {
		f.tool(name, `echo "$0 $*" >>`+shellQuote(f.tripLog)+"\nexit 0")
	}
	return f
}

// tool writes an executable fake named name whose body is the given sh code.
func (f *fakeEnv) tool(name, body string) {
	f.t.Helper()
	path := filepath.Join(f.bin, name)
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		f.t.Fatalf("write fake %s: %v", name, err)
	}
}

func (f *fakeEnv) golangciLint(version string) {
	f.tool("golangci-lint", `echo 'golangci-lint has version `+version+` built with go1.27.1 from (unknown, modified: ?, mod sum: "h1:fake") on (unknown)'`)
}

func (f *fakeEnv) gosec()       { f.tool("gosec", "exit 0") }
func (f *fakeEnv) govulncheck() { f.tool("govulncheck", `echo "Scanner: govulncheck@v1.8.0"`) }

// make runs a make target from the repo root with PATH holding only the fakes.
func (f *fakeEnv) make(target string) (string, error) {
	f.t.Helper()
	makeBin, err := exec.LookPath("make")
	if err != nil {
		f.t.Fatalf("make is required to exercise the CI targets: %v", err)
	}
	cmd := exec.Command(makeBin, "--no-print-directory", target)
	cmd.Dir = repoRoot
	cmd.Env = []string{
		"PATH=" + f.bin,
		"HOME=" + f.t.TempDir(),
		"CI_RUNNER_TOOLS_FILE=" + f.toolsFile,
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	return out.String(), err
}

// assertNoInstallAttempt fails the test if any tripwire was invoked.
func (f *fakeEnv) assertNoInstallAttempt() {
	f.t.Helper()
	data, err := os.ReadFile(f.tripLog)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		f.t.Fatalf("read tripwire log: %v", err)
	}
	f.t.Fatalf("a guard tried to install or fetch instead of failing closed:\n%s", data)
}

func mustFail(t *testing.T, out string, err error, want string) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected a non-zero exit, got err=%v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("output does not name the failure %q:\n%s", want, out)
	}
}

func mustPass(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected success, got %v\noutput:\n%s", err, out)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func TestVerifyLintTool_PinnedVersionPasses(t *testing.T) {
	pin := golangciLintPin(t)
	for _, reported := range []string{pin, "v" + pin} {
		t.Run(reported, func(t *testing.T) {
			f := newFakeEnv(t)
			f.golangciLint(reported)
			out, err := f.make("verify-lint-tool")
			mustPass(t, out, err)
			f.assertNoInstallAttempt()
		})
	}
}

func TestVerifyLintTool_OtherVersionFails(t *testing.T) {
	pin := golangciLintPin(t)
	cases := map[string]string{
		"the pre-1.27 pin":           "2.12.2",
		"pin as a prefix":            pin + "0",
		"pin with a suffix":          pin + "-rc.1",
		"a different patch":          "2.14.1",
		"version string unparseable": "dev",
	}
	for name, reported := range cases {
		t.Run(name, func(t *testing.T) {
			if reported == pin {
				t.Fatalf("case %q reports the pin itself", name)
			}
			f := newFakeEnv(t)
			f.golangciLint(reported)
			out, err := f.make("verify-lint-tool")
			mustFail(t, out, err, "is not version "+pin)
			f.assertNoInstallAttempt()
		})
	}
}

func TestVerifyLintTool_MissingFails(t *testing.T) {
	f := newFakeEnv(t)
	out, err := f.make("verify-lint-tool")
	mustFail(t, out, err, "golangci-lint is not on PATH")
	f.assertNoInstallAttempt()
}

func TestVerifyLintTool_VersionCommandErrorFails(t *testing.T) {
	f := newFakeEnv(t)
	f.tool("golangci-lint", "echo 'golangci-lint has version "+golangciLintPin(t)+" built with'; exit 3")
	out, err := f.make("verify-lint-tool")
	mustFail(t, out, err, "'golangci-lint version' failed")
	f.assertNoInstallAttempt()
}

func TestVerifySecurityTools_PresentPassesAndLogsImageRecord(t *testing.T) {
	f := newFakeEnv(t)
	f.gosec()
	f.govulncheck()
	const record = "gosec v2.99.0 (ldflags)"
	if err := os.WriteFile(f.toolsFile, []byte(record), 0o600); err != nil {
		t.Fatalf("write tools record: %v", err)
	}
	out, err := f.make("verify-security-tools")
	mustPass(t, out, err)
	for _, want := range []string{record, "govulncheck@v1.8.0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log does not record %q:\n%s", want, out)
		}
	}
	f.assertNoInstallAttempt()
}

func TestVerifySecurityTools_MissingToolFails(t *testing.T) {
	cases := map[string]struct {
		install func(*fakeEnv)
		want    string
	}{
		"gosec missing":       {func(f *fakeEnv) { f.govulncheck() }, "gosec is not on PATH"},
		"govulncheck missing": {func(f *fakeEnv) { f.gosec() }, "govulncheck is not on PATH"},
		"both missing":        {func(*fakeEnv) {}, "is not on PATH"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeEnv(t)
			tc.install(f)
			out, err := f.make("verify-security-tools")
			mustFail(t, out, err, tc.want)
			f.assertNoInstallAttempt()
		})
	}
}

func TestVerifySecurityTools_BrokenGovulncheckFails(t *testing.T) {
	f := newFakeEnv(t)
	f.gosec()
	f.tool("govulncheck", "exit 2")
	out, err := f.make("verify-security-tools")
	mustFail(t, out, err, "'govulncheck -version' failed")
	f.assertNoInstallAttempt()
}
