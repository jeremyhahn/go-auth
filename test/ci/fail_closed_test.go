package ci_test

// Regression tests for go-auth#66: `make lint` runs actionlint over the
// workflows, and neither actionlint nor trivy-fs can pass vacuously when its
// tool is missing. They reuse the fake-PATH harness of verify_tools_test.go:
// PATH holds only the fakes, so a missing tool really is missing.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder writes a fake that appends its arguments to a log and exits rc.
func (f *fakeEnv) recorder(name, rc string) string {
	f.t.Helper()
	log := filepath.Join(filepath.Dir(f.bin), name+".log")
	f.tool(name, `echo "$*" >>`+shellQuote(log)+"\nexit "+rc)
	return log
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the fake was never run: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func TestActionlint_MissingFails(t *testing.T) {
	f := newFakeEnv(t)
	f.recorder("shellcheck", "0")
	out, err := f.make("actionlint")
	mustFail(t, out, err, "actionlint is not installed")
	f.assertNoInstallAttempt()
}

// Without shellcheck actionlint disables its SC* rules and exits 0, so the
// target must refuse to run rather than report a half-checked pass.
func TestActionlint_MissingShellcheckFails(t *testing.T) {
	f := newFakeEnv(t)
	log := f.recorder("actionlint", "0")
	out, err := f.make("actionlint")
	mustFail(t, out, err, "shellcheck is not installed")
	if _, statErr := os.Stat(log); statErr == nil {
		t.Fatalf("actionlint ran without shellcheck:\n%s", out)
	}
	f.assertNoInstallAttempt()
}

func TestActionlint_FindingFails(t *testing.T) {
	f := newFakeEnv(t)
	f.recorder("shellcheck", "0")
	log := f.recorder("actionlint", "1")
	out, err := f.make("actionlint")
	mustFail(t, out, err, "actionlint")
	readLog(t, log)
}

func TestActionlint_CleanPasses(t *testing.T) {
	f := newFakeEnv(t)
	f.recorder("shellcheck", "0")
	log := f.recorder("actionlint", "0")
	out, err := f.make("actionlint")
	mustPass(t, out, err)
	readLog(t, log)
	f.assertNoInstallAttempt()
}

// `make lint` is the target CI runs; actionlint must be part of it, not a
// separate target nobody calls. -n prints the plan without running it.
func TestLint_IncludesActionlint(t *testing.T) {
	f := newFakeEnv(t)
	out, err := f.make("-n", "lint")
	mustPass(t, out, err)
	if !strings.Contains(out, "\nactionlint\n") {
		t.Fatalf("make lint does not run actionlint:\n%s", out)
	}
}

func TestTrivyFS_MissingFails(t *testing.T) {
	f := newFakeEnv(t)
	out, err := f.make("trivy-fs")
	mustFail(t, out, err, "trivy is not installed")
	f.assertNoInstallAttempt()
}

// The issue's verification: with trivy absent, `make security` exits non-zero
// even when every other analyser is present.
func TestSecurity_MissingTrivyFails(t *testing.T) {
	f := newFakeEnv(t)
	f.gosec()
	f.govulncheck()
	out, err := f.make("security")
	mustFail(t, out, err, "trivy is not installed")
}

func TestTrivyFS_KeepsScannersSeveritiesAndExitCode(t *testing.T) {
	f := newFakeEnv(t)
	log := f.recorder("trivy", "0")
	out, err := f.make("trivy-fs")
	mustPass(t, out, err)
	want := "fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 ."
	if got := readLog(t, log); got != want {
		t.Fatalf("trivy ran as %q, want %q", got, want)
	}
	f.assertNoInstallAttempt()
}

func TestTrivyFS_FindingFails(t *testing.T) {
	f := newFakeEnv(t)
	f.recorder("trivy", "1")
	out, err := f.make("trivy-fs")
	mustFail(t, out, err, "trivy fs")
}

// CI's lint job must put actionlint and shellcheck on PATH before `make lint`,
// or the now fail-closed target turns Lint red on a runner without them.
func TestWorkflow_LintInstallsActionlintAndShellcheckFirst(t *testing.T) {
	job, ok := loadCI(t).Jobs["lint"]
	if !ok {
		t.Fatal("ci.yml has no lint job")
	}
	needles := []string{"rhysd/actionlint/cmd/actionlint", "scripts/install-shellcheck.sh"}
	at := map[string]int{}
	lintAt := -1
	for i, s := range job.Steps {
		for _, n := range needles {
			if strings.Contains(s.Run, n) {
				if s.If != "" {
					t.Errorf("step %q is conditional (if=%q); both hosts need it", s.Name, s.If)
				}
				at[n] = i
			}
		}
		if strings.TrimSpace(s.Run) == "make lint" {
			lintAt = i
		}
	}
	if lintAt < 0 {
		t.Fatal("lint job never runs make lint")
	}
	for _, n := range needles {
		i, ok := at[n]
		if !ok {
			t.Errorf("lint job never runs %s", n)
		} else if i > lintAt {
			t.Errorf("lint job runs %s after make lint", n)
		}
	}
}
