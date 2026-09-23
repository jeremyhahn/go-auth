### Fixed

- Build: `make release-alpha` is replaced by the handbook's release-alpha
  template v2.3.9, vendored unmodified at `mk/release-alpha.mk` with its
  regression harness ([#22]). The old recipe guessed a patch-only bump,
  created lightweight unsigned tags as the local git identity, pushed every
  local tag to a `dev` remote this repo does not have, and let `|| true` hide
  a failed VERSION commit. A release is now
  `make release-alpha VERSION=vX.Y.Z-alpha`. It runs only on a clean `main`,
  makes every git write through `agent-git.sh` (found on `PATH`) as
  `go-auth`, and pushes the release commit and that one annotated tag to
  `origin`.
- Build: the release now assembles `changelog.d/` fragments
  (release-versioning.md §5). `make release-changelog`, which `release-alpha`
  runs first, folds every fragment and any existing `## [Unreleased]` content
  into a dated `## [X.Y.Z-alpha]` section (`scripts/changelog-assemble.sh`),
  deletes the fragments, and commits that before the tag is cut, so the
  tagged commit carries the entries. It refuses — before any commit — a
  misnamed fragment, a fragment with its own release heading, or fragments
  that would be stranded beside an existing section. `test/ci` runs the real
  Makefile against a throwaway remote, including a signing wrapper that
  rejects each commit, plus the template's own harness.

[#22]: https://github.com/jeremyhahn/go-auth/issues/22
