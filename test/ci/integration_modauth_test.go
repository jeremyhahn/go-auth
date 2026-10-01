package ci_test

// Regression tests for go-auth#42: every integration image build failed at
// `RUN go mod download` because go.mod requires the private
// github.com/jeremyhahn/go-enclave and `docker build` inherits none of the CI
// job's private-module configuration (dependency-resolution.md §6).
//
// The fix hands GOPRIVATE and the GIT_CONFIG_* rewrite to the build as an
// optional BuildKit secret, staged by scripts/docker-build-integration.sh.
// These tests pin both halves: the Dockerfiles mount the secret, the Makefiles
// build through the script, and the script stages the credentials outside the
// build context, keeps them off the command line, and removes them on every
// exit path.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	buildScript = "scripts/docker-build-integration.sh"
	secretID    = "gomodauth"
)

// modDownloadRun matches a RUN instruction, joined across its continuation
// lines, that ends in `go mod download`.
var modDownloadRun = regexp.MustCompile(`(?m)^RUN\b(?:[^\n]*\\\n)*[^\n]*go mod download`)

func TestIntegrationDockerfiles_ModDownloadMountsCredentialSecret(t *testing.T) {
	for _, path := range integrationDockerfiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		runs := modDownloadRun.FindAllString(string(data), -1)
		if len(runs) == 0 {
			t.Errorf("%s: no `RUN ... go mod download`; the image must pre-fetch modules so it needs no credentials at run time", path)
			continue
		}
		for _, run := range runs {
			if !strings.Contains(run, "--mount=type=secret,id="+secretID+",required=false") {
				t.Errorf("%s: `go mod download` does not mount the optional %q secret:\n%s", path, secretID, run)
			}
			if !strings.Contains(run, "/run/secrets/"+secretID) {
				t.Errorf("%s: `go mod download` does not source /run/secrets/%s:\n%s", path, secretID, run)
			}
		}
	}
}

// A credential passed as ARG lands in image metadata (`docker history`), and
// as ENV in every container the image spawns. Neither may carry one.
func TestIntegrationDockerfiles_NoCredentialsInArgOrEnv(t *testing.T) {
	leak := regexp.MustCompile(`(?im)^\s*(?:ARG|ENV)\b.*\b(?:GIT_CONFIG_|GOPRIVATE|TOKEN|GOPROXY=direct|GOSUMDB=off)`)
	for _, path := range integrationDockerfiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if m := leak.FindString(string(data)); m != "" {
			t.Errorf("%s: module credentials or checksum overrides in an image instruction: %q", path, m)
		}
	}
}

// bareDockerBuild matches a recipe line that calls docker build directly.
var bareDockerBuild = regexp.MustCompile(`(?m)^\t.*\$\(DOCKER\)\s+build\b`)

func TestIntegrationMakefiles_BuildThroughCredentialScript(t *testing.T) {
	for _, dockerfile := range integrationDockerfiles(t) {
		makefile := filepath.Join(filepath.Dir(dockerfile), "Makefile")
		data, err := os.ReadFile(makefile)
		if err != nil {
			t.Fatalf("read %s: %v", makefile, err)
		}
		if m := bareDockerBuild.FindString(string(data)); m != "" {
			t.Errorf("%s: builds its image with a bare docker build, which cannot resolve private modules: %q", makefile, strings.TrimSpace(m))
		}
		if !strings.Contains(string(data), buildScript) {
			t.Errorf("%s: does not build its image through %s", makefile, buildScript)
		}
	}
}

// scriptRun is one invocation of the build script against a fake docker that
// records its argv and copies the staged secret file before it is removed.
type scriptRun struct {
	out, argv, secretCopy, secretPath string
	secretMode                        os.FileMode
	err                               error
}

func runBuildScript(t *testing.T, dockerExit int, env ...string) scriptRun {
	t.Helper()
	return runBuildScriptIn(t, t.TempDir(), "", dockerExit, env...)
}

// runBuildScriptIn runs the script with its build context at dir/context and
// TMPDIR at tmpdir (dir when empty).
func runBuildScriptIn(t *testing.T, dir, tmpdir string, dockerExit int, env ...string) scriptRun {
	t.Helper()
	if tmpdir == "" {
		tmpdir = dir
	}
	argvLog := filepath.Join(dir, "argv")
	secretCopy := filepath.Join(dir, "secret-copy")
	secretPath := filepath.Join(dir, "secret-path")
	secretMode := filepath.Join(dir, "secret-mode")
	fakeDocker := filepath.Join(dir, "docker")
	body := `#!/bin/sh
printf '%s\n' "$@" >` + shellQuote(argvLog) + `
for a in "$@"; do
	case "$a" in
	id=` + secretID + `,src=*)
		src=${a#*src=}
		printf '%s' "$src" >` + shellQuote(secretPath) + `
		cp "$src" ` + shellQuote(secretCopy) + `
		ls -ln "$src" | cut -c1-10 >` + shellQuote(secretMode) + `
		;;
	esac
done
exit ` + string(rune('0'+dockerExit)) + "\n"
	if err := os.WriteFile(fakeDocker, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}

	contextDir := filepath.Join(dir, "context")
	if err := os.MkdirAll(contextDir, 0o755); err != nil {
		t.Fatalf("mkdir context: %v", err)
	}
	cmd := exec.Command("sh", filepath.Join(repoRoot, buildScript),
		filepath.Join(contextDir, "Dockerfile"), "go-auth-test:latest", contextDir)
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"DOCKER=" + fakeDocker,
		"TMPDIR=" + tmpdir,
	}, env...)
	out, err := cmd.CombinedOutput()

	r := scriptRun{out: string(out), err: err}
	if b, readErr := os.ReadFile(argvLog); readErr == nil {
		r.argv = string(b)
	}
	if b, readErr := os.ReadFile(secretCopy); readErr == nil {
		r.secretCopy = string(b)
	}
	if b, readErr := os.ReadFile(secretPath); readErr == nil {
		r.secretPath = string(b)
	}
	if b, readErr := os.ReadFile(secretMode); readErr == nil {
		mode, parseErr := parseLsMode(strings.TrimSpace(string(b)))
		if parseErr != nil {
			t.Fatalf("parse staged secret mode %q: %v", b, parseErr)
		}
		r.secretMode = mode
	}
	if r.secretPath != "" && strings.HasPrefix(r.secretPath, contextDir+string(filepath.Separator)) {
		t.Errorf("staged secret %s is inside the build context %s; `COPY . .` would bake it into a layer", r.secretPath, contextDir)
	}
	return r
}

// parseLsMode turns the permission column of `ls -l` ("-rw-------") into its
// permission bits. ls is used rather than stat because stat's flags differ
// between GNU and BSD.
func parseLsMode(s string) (os.FileMode, error) {
	if len(s) != 10 {
		return 0, errors.New("not an ls permission column")
	}
	var mode os.FileMode
	for i, c := range s[1:] {
		mode <<= 1
		switch {
		case c == '-':
		case c == rune("rwxrwxrwx"[i]):
			mode |= 1
		default:
			return 0, errors.New("unexpected permission character")
		}
	}
	return mode, nil
}

const fakeToken = "tok-do-not-leak-0123456789"

func credentialEnv() []string {
	return []string{
		"GOPRIVATE=github.com/jeremyhahn/*",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=url.http://x:" + fakeToken + "@gitea.invalid:3001/jeremyhahn/.insteadOf",
		"GIT_CONFIG_VALUE_0=https://github.com/jeremyhahn/",
	}
}

func TestDockerBuildIntegration_StagesCredentialsAsSecret(t *testing.T) {
	r := runBuildScript(t, 0, credentialEnv()...)
	if r.err != nil {
		t.Fatalf("script failed: %v\n%s", r.err, r.out)
	}
	for _, want := range []string{"build", "--secret", "-f", "-t", "go-auth-test:latest"} {
		if !strings.Contains(r.argv, want+"\n") {
			t.Errorf("docker argv missing %q:\n%s", want, r.argv)
		}
	}
	for _, want := range []string{
		"export GOPRIVATE='github.com/jeremyhahn/*'",
		"export GIT_CONFIG_COUNT='1'",
		"export GIT_CONFIG_KEY_0='url.http://x:" + fakeToken + "@gitea.invalid:3001/jeremyhahn/.insteadOf'",
		"export GIT_CONFIG_VALUE_0='https://github.com/jeremyhahn/'",
	} {
		if !strings.Contains(r.secretCopy, want) {
			t.Errorf("staged secret missing %q; got:\n%s", want, r.secretCopy)
		}
	}
	if r.secretMode != 0o600 {
		t.Errorf("staged secret mode = %o, want 600", r.secretMode)
	}
	if strings.Contains(r.argv, fakeToken) {
		t.Error("token reached the docker command line; it must travel only in the secret file")
	}
	if strings.Contains(r.out, fakeToken) {
		t.Error("token was printed to the build log")
	}
	if _, err := os.Stat(r.secretPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staged secret %s survived the build (stat err: %v)", r.secretPath, err)
	}
}

// Without credentials the same Dockerfile must still build: the mount is
// optional, the staged file is empty, and modules resolve from the public
// proxy -- the github.com shape.
func TestDockerBuildIntegration_NoCredentialsStillBuilds(t *testing.T) {
	r := runBuildScript(t, 0)
	if r.err != nil {
		t.Fatalf("script failed without credentials: %v\n%s", r.err, r.out)
	}
	if r.secretCopy != "" {
		t.Errorf("staged secret should be empty without credentials; got:\n%s", r.secretCopy)
	}
	if !strings.Contains(r.argv, "build\n") {
		t.Errorf("docker build was not run:\n%s", r.argv)
	}
}

func TestDockerBuildIntegration_FailedBuildFailsAndCleansUp(t *testing.T) {
	r := runBuildScript(t, 3, credentialEnv()...)
	var exitErr *exec.ExitError
	if !errors.As(r.err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("script must propagate docker's exit status 3; got err=%v\n%s", r.err, r.out)
	}
	if r.secretPath == "" {
		t.Fatal("docker was not handed a staged secret")
	}
	if _, err := os.Stat(r.secretPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staged secret %s survived a failed build (stat err: %v)", r.secretPath, err)
	}
}

// A value containing a single quote must not break out of the quoting in the
// file the Dockerfile sources.
func TestDockerBuildIntegration_QuotesValuesSafely(t *testing.T) {
	r := runBuildScript(t, 0,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=a'b;touch /tmp/pwned",
		"GIT_CONFIG_VALUE_0=v",
	)
	if r.err != nil {
		t.Fatalf("script failed: %v\n%s", r.err, r.out)
	}
	cmd := exec.Command("sh", "-c", `. "$1" && printf '%s' "$GIT_CONFIG_KEY_0"`, "sh", "/dev/stdin")
	cmd.Stdin = strings.NewReader(r.secretCopy)
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("source staged secret: %v", err)
	}
	if string(got) != "a'b;touch /tmp/pwned" {
		t.Errorf("round-tripped value = %q, want the literal input", got)
	}
}

// A TMPDIR inside the build context would put the staged credentials where
// `COPY . .` bakes them into a layer, and deleting the file afterwards cannot
// remove it from the image. The script must refuse before writing anything.
func TestDockerBuildIntegration_RefusesStagingInsideContext(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "context", "tmp")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested tmp: %v", err)
	}
	r := runBuildScriptIn(t, dir, nested, 0, credentialEnv()...)
	if r.err == nil {
		t.Fatalf("script accepted a staging directory inside the build context:\n%s", r.out)
	}
	if r.argv != "" {
		t.Errorf("docker ran despite the refusal:\n%s", r.argv)
	}
	entries, err := os.ReadDir(nested)
	if err != nil {
		t.Fatalf("read nested tmp: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("credentials were written inside the build context: %v", entries)
	}
}
