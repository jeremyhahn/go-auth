package ci_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// githubOnly is the one condition under which ci.yml may install an analyser:
// github.com-hosted runners have no ci-runner image, so nothing is baked there.
const githubOnly = "github.server_url == 'https://github.com'"

// analysers are the tools the ci-runner image bakes (go-auth#26).
var analysers = []string{"golangci-lint", "gosec", "govulncheck"}

// installVerbs are the ways a step could fetch a tool over the network.
var installVerbs = regexp.MustCompile(`\bgo install\b|\bgo get\b|\bcurl\b|\bwget\b|\bapt-get install\b|\bapk add\b`)

type workflow struct {
	Env  map[string]string `yaml:"env"`
	Jobs map[string]struct {
		Steps []step `yaml:"steps"`
	} `yaml:"jobs"`
}

type step struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
}

func loadCI(t *testing.T) workflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	return wf
}

// golangciLintPin reads the pin from the Makefile, the single place it lives.
func golangciLintPin(t *testing.T) string {
	t.Helper()
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Fatalf("make is required to read the golangci-lint pin: %v", err)
	}
	cmd := exec.Command(makeBin, "-s", "--no-print-directory", "print-golangci-lint-version")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("make print-golangci-lint-version: %v", err)
	}
	pin := strings.TrimSpace(string(out))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(pin) {
		t.Fatalf("golangci-lint pin %q is not an exact X.Y.Z version", pin)
	}
	return pin
}

func mentionsAnalyser(s string) bool {
	for _, a := range analysers {
		if strings.Contains(s, a) {
			return true
		}
	}
	return false
}

// No step may install an analyser on a Gitea runner: that is the install that
// overwrote the baked golangci-lint v2.14.0 with v2.12.2.
func TestWorkflow_AnalyserInstallsAreGithubOnly(t *testing.T) {
	wf := loadCI(t)
	for jobName, job := range wf.Jobs {
		for _, s := range job.Steps {
			installs := installVerbs.MatchString(s.Run) && mentionsAnalyser(s.Run)
			action := s.Uses != "" && mentionsAnalyser(s.Uses)
			if (installs || action) && strings.TrimSpace(s.If) != githubOnly {
				t.Errorf("job %s step %q installs an analyser with if=%q; only %q is allowed, Gitea must use the baked binary",
					jobName, s.Name, s.If, githubOnly)
			}
		}
	}
}

// requireGuardBefore asserts the guard step exists, runs unconditionally, and
// precedes every step that runs one of the guarded targets.
func requireGuardBefore(t *testing.T, wf workflow, jobName, guard string, guarded ...string) {
	t.Helper()
	job, ok := wf.Jobs[jobName]
	if !ok {
		t.Fatalf("ci.yml has no %s job", jobName)
	}
	guardAt := -1
	for i, s := range job.Steps {
		if strings.TrimSpace(s.Run) == guard {
			if s.If != "" {
				t.Errorf("job %s: %q is conditional (if=%q); it must run on every host", jobName, guard, s.If)
			}
			guardAt = i
			break
		}
	}
	if guardAt < 0 {
		t.Fatalf("job %s has no step running exactly %q", jobName, guard)
	}
	seen := map[string]bool{}
	for i, s := range job.Steps {
		for _, target := range guarded {
			if !strings.Contains(s.Run, target) {
				continue
			}
			seen[target] = true
			if i < guardAt {
				t.Errorf("job %s step %q runs %q before %q", jobName, s.Name, target, guard)
			}
		}
		if i > guardAt && installVerbs.MatchString(s.Run) && mentionsAnalyser(s.Run) {
			t.Errorf("job %s step %q installs an analyser after %q verified it", jobName, s.Name, guard)
		}
	}
	for _, target := range guarded {
		if !seen[target] {
			t.Errorf("job %s never runs %q, so the guard protects nothing", jobName, target)
		}
	}
}

func TestWorkflow_LintVerifiesToolBeforeLinting(t *testing.T) {
	requireGuardBefore(t, loadCI(t), "lint", "make verify-lint-tool", "make lint")
}

func TestWorkflow_SecurityVerifiesToolsBeforeScanning(t *testing.T) {
	requireGuardBefore(t, loadCI(t), "security", "make verify-security-tools", "make gosec", "make govulncheck")
}

// The github.com install must take its version from the Makefile pin, not a
// second copy of the number that can drift from it.
func TestWorkflow_GithubInstallUsesMakefilePin(t *testing.T) {
	wf := loadCI(t)
	for _, s := range wf.Jobs["lint"].Steps {
		if strings.Contains(s.Run, "golangci-lint@") &&
			!strings.Contains(s.Run, "golangci-lint@v$(make -s print-golangci-lint-version)") {
			t.Errorf("step %q installs golangci-lint at a version not read from the Makefile pin: %s", s.Name, s.Run)
		}
	}
}

var goDirective = regexp.MustCompile(`(?m)^go (\d+\.\d+(?:\.\d+)?)\s*$`)

func goModVersion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	m := goDirective.FindSubmatch(data)
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}
	return string(m[1])
}

// checkPinCoversDirective reports whether a CI GO_VERSION pin may build a
// module whose go directive is directive. The workflows and go.mod still move
// together, never piecemeal, but by the Company Agent convention (m2289 (4))
// each module's go directive stays on the lowest patch importers need while
// every CI pin carries the security patch (1.27.2 directive, 1.27.3 pin for
// GO-2026-6809). So the pin must share the directive's major.minor and its
// patch must be at or above the directive's.
func checkPinCoversDirective(file, pin, directive string) error {
	p, d := strings.Split(pin, "."), strings.Split(directive, ".")
	if len(p) != 3 || len(d) != 3 {
		return fmt.Errorf("%s GO_VERSION %q, go.mod directive %q: both must be major.minor.patch", file, pin, directive)
	}
	pp, perr := strconv.Atoi(p[2])
	dp, derr := strconv.Atoi(d[2])
	if perr != nil || derr != nil {
		return fmt.Errorf("%s GO_VERSION %q, go.mod directive %q: patch is not a number", file, pin, directive)
	}
	if p[0] != d[0] || p[1] != d[1] || pp < dp {
		return fmt.Errorf("%s GO_VERSION %q does not cover go.mod directive %q: the pin must be on the same minor at or above its patch, and the toolchain moves in one pass", file, pin, directive)
	}
	return nil
}

func TestCheckPinCoversDirective(t *testing.T) {
	for _, tc := range []struct {
		name, pin, directive string
		ok                   bool
	}{
		{"equal", "1.27.2", "1.27.2", true},
		{"higher patch", "1.27.3", "1.27.2", true},
		{"lower patch", "1.27.1", "1.27.2", false},
		{"other minor", "1.28.0", "1.27.2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPinCoversDirective("ci.yml", tc.pin, tc.directive)
			if (err == nil) != tc.ok {
				t.Fatalf("checkPinCoversDirective(%q, %q) = %v, want ok=%v", tc.pin, tc.directive, err, tc.ok)
			}
			if err != nil && (!strings.Contains(err.Error(), tc.pin) || !strings.Contains(err.Error(), tc.directive)) {
				t.Fatalf("error %q does not name both %q and %q", err, tc.pin, tc.directive)
			}
		})
	}
}

func TestWorkflow_GoVersionMatchesGoMod(t *testing.T) {
	if err := checkPinCoversDirective("ci.yml", loadCI(t).Env["GO_VERSION"], goModVersion(t)); err != nil {
		t.Fatal(err)
	}
}

func parseVersion(t *testing.T, v string) [3]int {
	t.Helper()
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("version %q: %v", v, err)
		}
		out[i] = n
	}
	return out
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// The go directive and the golangci-lint pin move together: v2.12.x cannot
// lint Go 1.27, and v2.13.0/v2.13.1 panicked on Go 1.26.
func TestLintPinMatchesGoDirective(t *testing.T) {
	goVer := parseVersion(t, goModVersion(t))
	pin := parseVersion(t, golangciLintPin(t))
	go127 := [3]int{1, 27, 0}
	lint2132 := [3]int{2, 13, 2}
	if !less(goVer, go127) && less(pin, lint2132) {
		t.Fatalf("go directive %v needs golangci-lint >= 2.13.2, pin is %v", goVer, pin)
	}
}
