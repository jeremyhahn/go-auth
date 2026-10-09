package ci_test

// Regression tests for go-auth#66: `make lint` runs actionlint over the
// workflows, and neither actionlint nor trivy-fs can pass vacuously when its
// tool is missing. They reuse the fake-PATH harness of verify_tools_test.go:
// PATH holds only the fakes, so a missing tool really is missing.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// giteaOnly is the condition of a step that runs on Gitea runners alone.
const giteaOnly = "github.server_url != 'https://github.com'"

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
	for _, p := range lintToolProblems(job.Steps) {
		t.Error(p)
	}
}

// lintToolProblems checks the lint job's steps. shellcheck must install
// unconditionally before make lint. actionlint must either install
// unconditionally, or install on github.com only and be backed by a Gitea-only
// `command -v actionlint` assertion (the runner image bakes it); each before
// make lint.
func lintToolProblems(steps []step) []string {
	const actionlintNeedle = "rhysd/actionlint/cmd/actionlint"
	const shellcheckNeedle = "scripts/install-shellcheck.sh"
	var problems []string
	lintAt, installAt, shellcheckAt, assertAt := -1, -1, -1, -1
	installIf := ""
	for i, s := range steps {
		if strings.Contains(s.Run, actionlintNeedle) {
			installAt, installIf = i, strings.TrimSpace(s.If)
		}
		if strings.Contains(s.Run, shellcheckNeedle) {
			if s.If != "" {
				problems = append(problems, fmt.Sprintf("step %q is conditional (if=%q); both hosts need it", s.Name, s.If))
			}
			shellcheckAt = i
		}
		if strings.TrimSpace(s.If) == giteaOnly && strings.Contains(s.Run, "command -v actionlint") {
			assertAt = i
		}
		if strings.TrimSpace(s.Run) == "make lint" {
			lintAt = i
		}
	}
	if lintAt < 0 {
		return append(problems, "lint job never runs make lint")
	}
	if shellcheckAt < 0 {
		problems = append(problems, "lint job never runs "+shellcheckNeedle)
	} else if shellcheckAt > lintAt {
		problems = append(problems, "lint job runs "+shellcheckNeedle+" after make lint")
	}
	switch {
	case installAt < 0:
		problems = append(problems, "lint job never runs "+actionlintNeedle)
	case installAt > lintAt:
		problems = append(problems, "lint job runs "+actionlintNeedle+" after make lint")
	case installIf == "":
		// Unconditional install: both hosts covered.
	case installIf != githubOnly:
		problems = append(problems, fmt.Sprintf("actionlint install has if=%q; only unconditional or %q is allowed", installIf, githubOnly))
	case assertAt < 0:
		problems = append(problems, "actionlint install is github.com only but no Gitea-only `command -v actionlint` step asserts the baked tool")
	case assertAt > lintAt:
		problems = append(problems, "baked actionlint assertion runs after make lint")
	}
	return problems
}

func TestLintToolProblems(t *testing.T) {
	install := step{Name: "Install actionlint", Run: "go install github.com/rhysd/actionlint/cmd/actionlint@latest"}
	shellcheck := step{Name: "Install shellcheck", Run: "./scripts/install-shellcheck.sh bin"}
	assert := step{Name: "Assert", If: giteaOnly, Run: "command -v actionlint"}
	lint := step{Name: "Lint", Run: "make lint"}
	ghInstall := install
	ghInstall.If = githubOnly

	tests := []struct {
		name  string
		steps []step
		ok    bool
	}{
		{"unconditional install", []step{install, shellcheck, lint}, true},
		{"github install plus gitea assertion", []step{ghInstall, assert, shellcheck, lint}, true},
		{"github install without assertion", []step{ghInstall, shellcheck, lint}, false},
		{"assertion not gitea-only", []step{ghInstall, {Name: "A", Run: "command -v actionlint"}, shellcheck, lint}, false},
		{"assertion after make lint", []step{ghInstall, shellcheck, lint, assert}, false},
		{"install after make lint", []step{shellcheck, lint, install}, false},
		{"no install", []step{shellcheck, lint}, false},
		{"conditional shellcheck", []step{install, {Name: "sc", If: githubOnly, Run: shellcheck.Run}, lint}, false},
		{"no shellcheck", []step{install, lint}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lintToolProblems(tc.steps)
			if tc.ok && len(got) > 0 {
				t.Errorf("want accepted, got %v", got)
			}
			if !tc.ok && len(got) == 0 {
				t.Error("want rejected, got accepted")
			}
		})
	}
}
