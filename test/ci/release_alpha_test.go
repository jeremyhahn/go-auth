package ci_test

// Regression tests for go-auth#22: the v1 `release-alpha` recipe guessed a
// PATCH-only version, cut lightweight unsigned tags as the local git identity,
// pushed every local tag and swallowed a failed VERSION commit with `|| true`.
// The Makefile now includes the handbook's release-alpha template (v2.3.9,
// vendored at mk/release-alpha.mk). These tests run the repository's REAL
// Makefile against a throwaway bare remote — never a real one — with a stub
// agent-git.sh that records how it was called and then runs plain git.

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const templateHeader = "# release-alpha-template: v2.3.9 "

// releaseFixture is a clone of a bare remote, on main, holding this repo's
// Makefile and vendored template, with a private HOME and git config.
type releaseFixture struct {
	t      *testing.T
	work   string
	remote string
	stub   string // directory holding the agent-git.sh stub
	calls  string // log of the stub's argument vectors
	env    []string
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	return newReleaseFixtureWith(t, "# Changelog\n\n## [9.9.9-alpha]\n", nil)
}

// newReleaseFixtureWith commits the given CHANGELOG.md and changelog.d/
// fragments (name -> content) as the fixture's initial state.
func newReleaseFixtureWith(t *testing.T, changelog string, fragments map[string]string) *releaseFixture {
	t.Helper()
	for _, tool := range []string{"git", "make", "sh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required to exercise release-alpha: %v", tool, err)
		}
	}
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	f := &releaseFixture{
		t:      t,
		work:   filepath.Join(dir, "work"),
		remote: filepath.Join(dir, "remote.git"),
		stub:   filepath.Join(dir, "stub"),
		calls:  filepath.Join(dir, "agent-git.calls"),
	}
	for _, d := range []string{home, f.work, f.stub, filepath.Join(f.work, "mk"), filepath.Join(f.work, "scripts"), filepath.Join(f.work, "changelog.d")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	f.env = []string{
		"PATH=" + f.stub + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=" + filepath.Join(home, "gitconfig"),
		"GIT_CONFIG_NOSYSTEM=1",
	}
	// The stub logs its argv, then runs plain git — unless AGENT_GIT_REJECT
	// names the git verb, which it rejects the way a failed signing would.
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(f.calls) +
		"\nif [ -n \"$AGENT_GIT_REJECT\" ] && [ \"$2\" = \"$AGENT_GIT_REJECT\" ]; then echo \"agent-git.sh: signing refused $2\" >&2; exit 1; fi" +
		"\nshift\nexec git \"$@\"\n"
	if err := os.WriteFile(filepath.Join(f.stub, "agent-git.sh"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write agent-git.sh stub: %v", err)
	}
	copyFile(t, filepath.Join(repoRoot, "Makefile"), filepath.Join(f.work, "Makefile"))
	copyFile(t, filepath.Join(repoRoot, "mk", "release-alpha.mk"), filepath.Join(f.work, "mk", "release-alpha.mk"))
	writeFile(t, filepath.Join(f.work, "VERSION"), "0.0.1-alpha\n")
	copyFile(t, filepath.Join(repoRoot, "scripts", "changelog-assemble.sh"), filepath.Join(f.work, "scripts", "changelog-assemble.sh"))
	writeFile(t, filepath.Join(f.work, "CHANGELOG.md"), changelog)
	writeFile(t, filepath.Join(f.work, "changelog.d", ".gitkeep"), "")
	for name, content := range fragments {
		writeFile(t, filepath.Join(f.work, "changelog.d", name), content)
	}

	for _, args := range [][]string{
		{"config", "--global", "user.name", "fixture"},
		{"config", "--global", "user.email", "fixture@example.invalid"},
		{"config", "--global", "init.defaultBranch", "main"},
		{"config", "--global", "commit.gpgSign", "false"},
		{"config", "--global", "tag.gpgSign", "false"},
		{"init", "-q", "--bare", f.remote},
	} {
		f.git(dir, args...)
	}
	f.git(f.work, "init", "-q")
	f.git(f.work, "remote", "add", "origin", f.remote)
	// A pre-existing, unrelated LOCAL tag: v1 pushed it with --tags.
	f.git(f.work, "add", ".")
	f.git(f.work, "commit", "-q", "-m", "initial")
	f.git(f.work, "tag", "v0.0.8-stale")
	f.git(f.work, "push", "-q", "origin", "main")
	return f
}

func (f *releaseFixture) git(dir string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = f.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (f *releaseFixture) release(args ...string) (string, error) {
	f.t.Helper()
	cmd := exec.Command("make", append([]string{"-s", "--no-print-directory", "release-alpha"}, args...)...)
	cmd.Dir = f.work
	cmd.Env = f.env
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func (f *releaseFixture) remoteTags() []string {
	f.t.Helper()
	var tags []string
	for _, line := range strings.Split(f.git(f.work, "ls-remote", "--tags", "--refs", "origin"), "\n") {
		if i := strings.Index(line, "refs/tags/"); i >= 0 {
			tags = append(tags, line[i+len("refs/tags/"):])
		}
	}
	return tags
}

func TestReleaseAlpha_PublishesOnlyTheNamedAnnotatedTagThroughAgentGit(t *testing.T) {
	f := newReleaseFixture(t)
	out, err := f.release("VERSION=v9.9.9-alpha")
	mustPass(t, out, err)

	if got := f.remoteTags(); len(got) != 1 || got[0] != "v9.9.9-alpha" {
		t.Fatalf("remote tags = %q, want only v9.9.9-alpha (v1 pushed every local tag)", got)
	}
	if typ := f.git(f.work, "cat-file", "-t", "refs/tags/v9.9.9-alpha"); typ != "tag" {
		t.Fatalf("v9.9.9-alpha is a %s object, want an annotated tag", typ)
	}
	head := f.git(f.work, "rev-parse", "HEAD")
	if remote := strings.Fields(f.git(f.work, "ls-remote", "origin", "refs/heads/main")); len(remote) == 0 || remote[0] != head {
		t.Fatalf("remote main %q is not the release commit %s", remote, head)
	}
	data, err := os.ReadFile(filepath.Join(f.work, "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if string(data) != "9.9.9-alpha\n" {
		t.Fatalf("VERSION = %q, want the unprefixed %q", data, "9.9.9-alpha\n")
	}

	// Every git write went through agent-git.sh, resolved from PATH, signing
	// as this repository's literal name.
	calls, err := os.ReadFile(f.calls)
	if err != nil {
		t.Fatalf("agent-git.sh was never called: %v", err)
	}
	var verbs []string
	sc := bufio.NewScanner(bytes.NewReader(calls))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "go-auth" {
			t.Fatalf("agent-git.sh called as %q, want REPO_NAME go-auth first", sc.Text())
		}
		verbs = append(verbs, fields[1])
	}
	if want := "add commit tag push"; strings.Join(verbs, " ") != want {
		t.Fatalf("agent-git.sh verbs = %q, want %q", verbs, want)
	}
	if !strings.Contains(string(calls), "push --atomic --no-follow-tags origin HEAD refs/tags/v9.9.9-alpha") {
		t.Fatalf("release push does not name only the tag on origin:\n%s", calls)
	}
}

func TestReleaseAlpha_RefusesWithoutAnExplicitVersion(t *testing.T) {
	cases := map[string]struct {
		args []string
		want string
	}{
		"no VERSION (v1 guessed a patch bump)": {nil, "state the version explicitly"},
		"malformed VERSION":                    {[]string{"VERSION=0.3.0-alpha"}, "is not of the form vX.Y.Z-alpha"},
		"no CHANGELOG section":                 {[]string{"VERSION=v9.9.8-alpha"}, "CHANGELOG.md has no"},
		"unresolvable agent-git.sh":            {[]string{"VERSION=v9.9.9-alpha", "AGENT_GIT="}, "AGENT_GIT does not point at an executable"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newReleaseFixture(t)
			head := f.git(f.work, "rev-parse", "HEAD")
			out, err := f.release(tc.args...)
			mustFail(t, out, err, tc.want)
			if got := f.git(f.work, "rev-parse", "HEAD"); got != head {
				t.Fatalf("a refused release committed: HEAD %s -> %s", head, got)
			}
			if st := f.git(f.work, "status", "--porcelain"); st != "" {
				t.Fatalf("a refused release modified the tree:\n%s", st)
			}
			if tags := f.remoteTags(); len(tags) != 0 {
				t.Fatalf("a refused release pushed tags %q", tags)
			}
			if _, err := os.Stat(f.calls); err == nil {
				t.Fatalf("a refused release reached agent-git.sh")
			}
		})
	}
}

// v1 ran `git commit ... || true` and tagged and pushed anyway, so a failed
// VERSION commit still published a tag. A rejected commit must now stop the
// release before any tag exists, locally or on the remote.
func TestReleaseAlpha_FailedVersionCommitPublishesNothing(t *testing.T) {
	f := newReleaseFixture(t)
	f.env = append(f.env, "AGENT_GIT_REJECT=commit")
	remoteMain := f.git(f.work, "ls-remote", "origin", "refs/heads/main")

	out, err := f.release("VERSION=v9.9.9-alpha")
	mustFail(t, out, err, "signing refused commit")

	if f.git(f.work, "tag", "--list", "v9.9.9-alpha") != "" {
		t.Fatalf("a failed VERSION commit still created the local tag:\n%s", out)
	}
	if tags := f.remoteTags(); len(tags) != 0 {
		t.Fatalf("a failed VERSION commit still pushed tags %q:\n%s", tags, out)
	}
	if got := f.git(f.work, "ls-remote", "origin", "refs/heads/main"); got != remoteMain {
		t.Fatalf("remote main moved after a failed VERSION commit: %q -> %q", remoteMain, got)
	}
	calls, err := os.ReadFile(f.calls)
	if err != nil {
		t.Fatalf("read agent-git.sh calls: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if verb := strings.Fields(line); len(verb) > 1 && (verb[1] == "tag" || verb[1] == "push") {
			t.Fatalf("the recipe went on to %q after the commit failed", line)
		}
	}
}

// The vendored template is the handbook's v2.3.9, unmodified; its own
// regression harness (vendored beside it) must pass against it.
func TestReleaseAlpha_VendoredTemplateHarness(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "mk", "release-alpha.mk"))
	if err != nil {
		t.Fatalf("read vendored template: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(templateHeader)) {
		t.Fatalf("mk/release-alpha.mk does not start with %q", templateHeader)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("bash is required to run the template harness: %v", err)
	}
	cmd := exec.Command("bash", filepath.Join("mk", "testdata", "release-alpha-tests.sh"))
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("release-alpha template harness failed: %v\n%s", err, out)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	writeFile(t, dst, string(data))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
