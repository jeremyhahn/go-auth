package ci_test

// Regression tests for the changelog.d/ assembly step of go-auth#22
// (release-versioning.md §5): `make release-alpha` runs `release-changelog`
// first, which folds every fragment into the version's CHANGELOG.md section,
// deletes the fragments, and commits that BEFORE the tag is cut — so the
// tagged commit carries the assembled entries and no fragment is stranded.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const assemblyChangelog = `# Changelog

## [Unreleased]

### Fixed

- old fix ([#1]).

[#1]: https://example.invalid/1

## [0.0.1-alpha] - 2026-01-01

### Added

- first.
`

var assemblyFragments = map[string]string{
	"22-release.md": "### Fixed\n\n- fragment fix ([#22]).\n\n[#22]: https://example.invalid/22\n",
	"3-thing.md":    "### Added\n\n- fragment add ([#3]).\n\n[#3]: https://example.invalid/3\n[#1]: https://example.invalid/1\n",
}

// agentGitVerbs is the sequence of git verbs the recipe ran through the stub.
func (f *releaseFixture) agentGitVerbs() []string {
	f.t.Helper()
	data, err := os.ReadFile(f.calls)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatalf("read agent-git.sh calls: %v", err)
	}
	var verbs []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if fields := strings.Fields(line); len(fields) > 1 {
			verbs = append(verbs, fields[1])
		}
	}
	return verbs
}

func TestReleaseAlpha_TaggedCommitCarriesAssembledFragments(t *testing.T) {
	f := newReleaseFixtureWith(t, assemblyChangelog, assemblyFragments)
	out, err := f.release("VERSION=v9.9.9-alpha")
	mustPass(t, out, err)

	if got, want := strings.Join(f.agentGitVerbs(), " "), "add commit add commit tag push"; got != want {
		t.Fatalf("agent-git.sh verbs = %q, want %q (assembly commit, then the release)", got, want)
	}
	if got, want := f.git(f.work, "log", "--format=%s", "-3", "v9.9.9-alpha"), "chore(release): v9.9.9-alpha\ndocs(changelog): assemble v9.9.9-alpha\ninitial"; got != want {
		t.Fatalf("history under the tag:\n%s\nwant:\n%s", got, want)
	}
	if got := f.git(f.work, "ls-tree", "--name-only", "v9.9.9-alpha", "changelog.d/"); got != "changelog.d/.gitkeep" {
		t.Fatalf("the tagged tree still holds fragments:\n%s", got)
	}
	head := f.git(f.work, "rev-parse", "HEAD")
	if remote := strings.Fields(f.git(f.work, "ls-remote", "origin", "refs/heads/main")); len(remote) == 0 || remote[0] != head {
		t.Fatalf("remote main %q is not the release commit %s", remote, head)
	}

	cl := f.git(f.work, "show", "v9.9.9-alpha:CHANGELOG.md") + "\n"
	heading := regexp.MustCompile(`(?m)^## \[9\.9\.9-alpha\] - \d{4}-\d{2}-\d{2}$`).FindStringIndex(cl)
	if heading == nil {
		t.Fatalf("tagged CHANGELOG.md has no dated ## [9.9.9-alpha] heading:\n%s", cl)
	}
	unreleased := strings.Index(cl, "## [Unreleased]\n")
	prior := strings.Index(cl, "## [0.0.1-alpha] - 2026-01-01\n")
	if unreleased < 0 || prior < 0 || !(unreleased < heading[0] && heading[1] < prior) {
		t.Fatalf("## [9.9.9-alpha] is not between ## [Unreleased] and the previous release:\n%s", cl)
	}
	if between := strings.TrimSpace(cl[unreleased+len("## [Unreleased]\n") : heading[0]]); between != "" {
		t.Fatalf("## [Unreleased] was not emptied; it still holds:\n%s", between)
	}
	section := cl[heading[1]:prior]
	want := "\n\n### Fixed\n\n- old fix ([#1]).\n- fragment fix ([#22]).\n\n" +
		"### Added\n\n- fragment add ([#3]).\n\n" +
		"[#1]: https://example.invalid/1\n[#3]: https://example.invalid/3\n[#22]: https://example.invalid/22\n\n"
	if section != want {
		t.Fatalf("assembled section:\n%q\nwant (one ### per subsection, fragments in issue order, link definitions once):\n%q", section, want)
	}
	if !strings.HasSuffix(cl, "## [0.0.1-alpha] - 2026-01-01\n\n### Added\n\n- first.\n") {
		t.Fatalf("the previous release's section changed:\n%s", cl)
	}
}

// §5 migration: content already under ## [Unreleased] releases normally even
// when no fragment exists yet.
func TestReleaseAlpha_UnreleasedContentWithoutFragmentsIsReleased(t *testing.T) {
	f := newReleaseFixtureWith(t, assemblyChangelog, nil)
	out, err := f.release("VERSION=v9.9.9-alpha")
	mustPass(t, out, err)
	cl := f.git(f.work, "show", "v9.9.9-alpha:CHANGELOG.md")
	if !regexp.MustCompile(`(?m)^## \[9\.9\.9-alpha\] - \d{4}-\d{2}-\d{2}\n\n### Fixed\n\n- old fix \(\[#1\]\)\.\n\n\[#1\]: https://example\.invalid/1\n\n## \[0\.0\.1-alpha\]`).MatchString(cl) {
		t.Fatalf("Unreleased content was not released as ## [9.9.9-alpha]:\n%s", cl)
	}
}

func TestReleaseAlpha_AssemblyRefusalsPublishNothing(t *testing.T) {
	cases := map[string]struct {
		changelog string
		fragments map[string]string
		setup     func(*releaseFixture)
		want      string
	}{
		"fragments beside an existing section would be stranded": {
			changelog: "# Changelog\n\n## [Unreleased]\n\n## [9.9.9-alpha]\n\n### Fixed\n\n- x.\n",
			fragments: assemblyFragments,
			want:      "would be stranded",
		},
		"a fragment not named <issue>-<slug>.md": {
			changelog: assemblyChangelog,
			fragments: map[string]string{"notes.md": "### Fixed\n\n- x.\n"},
			want:      "is not an <issue>-<slug>.md fragment",
		},
		"a fragment with its own release heading": {
			changelog: assemblyChangelog,
			fragments: map[string]string{"7-bad.md": "## [9.9.9-alpha]\n\n### Fixed\n\n- x.\n"},
			want:      "carries its own",
		},
		"no Unreleased heading to assemble under": {
			changelog: "# Changelog\n\n## [0.0.1-alpha] - 2026-01-01\n",
			fragments: assemblyFragments,
			want:      "no ## [Unreleased] heading",
		},
		"the tag already exists on the remote": {
			changelog: assemblyChangelog,
			fragments: assemblyFragments,
			setup: func(f *releaseFixture) {
				f.git(f.work, "tag", "v9.9.9-alpha")
				f.git(f.work, "push", "-q", "origin", "refs/tags/v9.9.9-alpha")
				f.git(f.work, "tag", "-d", "v9.9.9-alpha")
			},
			want: "already exists on origin",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newReleaseFixtureWith(t, tc.changelog, tc.fragments)
			if tc.setup != nil {
				tc.setup(f)
			}
			head := f.git(f.work, "rev-parse", "HEAD")
			remoteTags := f.remoteTags()
			out, err := f.release("VERSION=v9.9.9-alpha")
			mustFail(t, out, err, tc.want)
			if got := f.git(f.work, "rev-parse", "HEAD"); got != head {
				t.Fatalf("a refused release committed: HEAD %s -> %s", head, got)
			}
			if st := f.git(f.work, "status", "--porcelain"); st != "" {
				t.Fatalf("a refused release modified the tree:\n%s", st)
			}
			if got := f.remoteTags(); strings.Join(got, " ") != strings.Join(remoteTags, " ") {
				t.Fatalf("a refused release changed the remote tags: %q -> %q", remoteTags, got)
			}
			if verbs := f.agentGitVerbs(); len(verbs) != 0 {
				t.Fatalf("a refused release reached agent-git.sh: %q", verbs)
			}
		})
	}
}

// A rejected assembly commit must stop the release: nothing tagged, nothing
// pushed, and the fragments are still committed in HEAD to retry from.
func TestReleaseAlpha_FailedAssemblyCommitPublishesNothing(t *testing.T) {
	f := newReleaseFixtureWith(t, assemblyChangelog, assemblyFragments)
	f.env = append(f.env, "AGENT_GIT_REJECT=commit")
	remoteMain := f.git(f.work, "ls-remote", "origin", "refs/heads/main")

	out, err := f.release("VERSION=v9.9.9-alpha")
	mustFail(t, out, err, "signing refused commit")
	// It must stop AT the failed commit. Were the failure swallowed, the
	// template's clean-tree guard would still refuse one step later — the
	// release would not publish, but only by luck of the next guard.
	if strings.Contains(out, "working tree not clean") {
		t.Fatalf("the failed assembly commit was swallowed; the template's clean-tree guard caught it instead:\n%s", out)
	}

	if got, want := strings.Join(f.agentGitVerbs(), " "), "add commit"; got != want {
		t.Fatalf("agent-git.sh verbs = %q, want %q — the release went on after the assembly commit failed", got, want)
	}
	if f.git(f.work, "tag", "--list", "v9.9.9-alpha") != "" {
		t.Fatalf("a failed assembly commit still created the local tag")
	}
	if tags := f.remoteTags(); len(tags) != 0 {
		t.Fatalf("a failed assembly commit still pushed tags %q", tags)
	}
	if got := f.git(f.work, "ls-remote", "origin", "refs/heads/main"); got != remoteMain {
		t.Fatalf("remote main moved after a failed assembly commit: %q -> %q", remoteMain, got)
	}
	if f.git(f.work, "cat-file", "-t", "HEAD:changelog.d/22-release.md") != "blob" {
		t.Fatalf("the fragment is gone from HEAD after a failed assembly commit")
	}
}

// Fenced code is content, not structure (go-auth#22 review): a "# comment"
// or "### Added" line inside a fence is neither a heading nor a subsection
// boundary, a "[x]: y" line inside one is not a link definition, and the
// block reaches the tagged CHANGELOG.md verbatim — blank lines included.
func TestReleaseAlpha_FencedCodeInFragmentsIsKeptVerbatim(t *testing.T) {
	shell := "```sh\n# install the tool\nmake release-alpha VERSION=v1.2.3-alpha\n\n\n## not a heading\n```"
	example := "~~~~markdown\n### Added\n\n- looks like an entry.\n~~~\n[#9]: https://example.invalid/not-a-ref\n~~~~"
	unreleased := "```\n### Removed\n```"
	changelog := strings.Replace(assemblyChangelog, "- old fix ([#1]).\n", "- old fix ([#1]).\n\n"+unreleased+"\n", 1)
	fragments := map[string]string{
		"5-shell.md":   "### Fixed\n\n- fix with a shell example ([#5]):\n\n" + shell + "\n\n[#5]: https://example.invalid/5\n",
		"6-example.md": "### Changed\n\n- documented heading syntax ([#6]):\n\n" + example + "\n",
	}
	f := newReleaseFixtureWith(t, changelog, fragments)
	out, err := f.release("VERSION=v9.9.9-alpha")
	mustPass(t, out, err)

	cl := f.git(f.work, "show", "v9.9.9-alpha:CHANGELOG.md") + "\n"
	heading := regexp.MustCompile(`(?m)^## \[9\.9\.9-alpha\] - \d{4}-\d{2}-\d{2}$`).FindStringIndex(cl)
	prior := strings.Index(cl, "## [0.0.1-alpha] - 2026-01-01\n")
	if heading == nil || prior < heading[1] {
		t.Fatalf("tagged CHANGELOG.md has no ## [9.9.9-alpha] section before the previous release:\n%s", cl)
	}
	want := "\n\n### Fixed\n\n- old fix ([#1]).\n\n" + unreleased + "\n" +
		"- fix with a shell example ([#5]):\n\n" + shell + "\n\n" +
		"### Changed\n\n- documented heading syntax ([#6]):\n\n" + example + "\n\n" +
		"[#1]: https://example.invalid/1\n[#5]: https://example.invalid/5\n\n"
	if section := cl[heading[1]:prior]; section != want {
		t.Fatalf("assembled section:\n%q\nwant (fenced blocks verbatim, no heading or link definition taken from inside them):\n%q", section, want)
	}
	if got := f.git(f.work, "ls-tree", "--name-only", "v9.9.9-alpha", "changelog.d/"); got != "changelog.d/.gitkeep" {
		t.Fatalf("the tagged tree still holds fragments:\n%s", got)
	}
}

// A fence left open would swallow the rest of the section into a code block;
// the release refuses instead, before anything is committed or pushed.
func TestReleaseAlpha_UnclosedFenceRefusesRelease(t *testing.T) {
	cases := map[string]struct {
		changelog string
		fragments map[string]string
	}{
		"in a fragment followed by another": {
			changelog: assemblyChangelog,
			fragments: map[string]string{
				"4-open.md": "### Fixed\n\n- x:\n\n```sh\n# never closed\n",
				"8-next.md": "### Added\n\n- y.\n",
			},
		},
		"in the last fragment": {
			changelog: assemblyChangelog,
			fragments: map[string]string{"4-open.md": "### Fixed\n\n- x:\n\n~~~\n### Added\n"},
		},
		"closed by a shorter fence": {
			changelog: assemblyChangelog,
			fragments: map[string]string{"4-open.md": "### Fixed\n\n- x:\n\n````\ncode\n```\n"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newReleaseFixtureWith(t, tc.changelog, tc.fragments)
			head := f.git(f.work, "rev-parse", "HEAD")
			out, err := f.release("VERSION=v9.9.9-alpha")
			mustFail(t, out, err, "leaves a fenced code block open")
			if got := f.git(f.work, "rev-parse", "HEAD"); got != head {
				t.Fatalf("a refused release committed: HEAD %s -> %s", head, got)
			}
			if st := f.git(f.work, "status", "--porcelain"); st != "" {
				t.Fatalf("a refused release modified the tree:\n%s", st)
			}
			if tags := f.remoteTags(); len(tags) != 0 {
				t.Fatalf("a refused release pushed tags %q", tags)
			}
			if verbs := f.agentGitVerbs(); len(verbs) != 0 {
				t.Fatalf("a refused release reached agent-git.sh: %q", verbs)
			}
		})
	}
}
