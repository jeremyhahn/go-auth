#!/usr/bin/env bash
# release-alpha-tests.sh — runs the release-alpha template for real, against a
# throwaway bare remote, and asserts what reached that remote. go-quicbaas#967:
#
#   1. push.followTags=true (a common global setting) made the release push
#      publish every missing annotated tag reachable from HEAD, not just the one
#      named on the command line — --atomic does not narrow that set.
#   2. A fenced code block quoting "## [X.Y.Z-alpha]" at column one satisfied
#      the CHANGELOG guard, so a release with no real section was cut and pushed.
#
# Nothing here touches the caller's git config or any real remote: HOME and the
# global config are private to each case, and AGENT_GIT is a stub that runs
# plain git (signing is agent-git.sh's contract, not this recipe's).
#
#   bash software/templates/make/testdata/release-alpha-tests.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/../release-alpha.mk"
[ -f "$TEMPLATE" ] || { echo "FATAL: no template at $TEMPLATE — the test would measure nothing"; exit 9; }

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
VER=v0.1.0-alpha
HEADING="## [${VER#v}]"
FENCE='```'
LONG_FENCE='````'

ok()  { printf '  PASS  %s\n' "$1"; }
bad() { printf '  FAIL  %s: %s\n' "$1" "$2"; return 1; }

# fixture <case-dir> — a clone of a bare remote on main, with the template
# included exactly as an adopter includes it. Leaves the caller in the clone.
fixture() {
	local dir="$ROOT/$1"
	mkdir -p "$dir/home"
	export HOME="$dir/home" GIT_CONFIG_GLOBAL="$dir/home/gitconfig" GIT_CONFIG_NOSYSTEM=1
	git config --global user.name fixture
	git config --global user.email fixture@example.invalid
	git config --global init.defaultBranch main
	git config --global tag.gpgSign false
	git config --global commit.gpgSign false

	git init -q --bare "$dir/remote.git"
	git init -q "$dir/work"
	cd "$dir/work" || exit 9
	git remote add origin "$dir/remote.git"

	printf '#!/bin/sh\nshift\nexec git "$@"\n' > "$dir/agent-git"
	chmod +x "$dir/agent-git"
	cat > Makefile <<EOF
AGENT_GIT ?= $dir/agent-git
REPO_NAME ?= fixture
RELEASE_REMOTE ?= origin
include $TEMPLATE
EOF
	printf '0.0.1-alpha\n' > VERSION
	printf '# Changelog\n' > CHANGELOG.md
	git add Makefile VERSION CHANGELOG.md
	git commit -q -m initial
	git push -q origin main
}

# changelog <body> — commit a CHANGELOG.md and publish it, so the tree is clean
# and the remote is level with HEAD before the recipe runs.
changelog() {
	printf '# Changelog\n\n%s\n' "$1" > CHANGELOG.md
	git commit -q -am changelog
	git push -q origin main
}

release() { make -s release-alpha VERSION="$VER" >"$ROOT/out" 2>&1; }

remote_tags() { git ls-remote --tags --refs origin | sed 's|.*refs/tags/||' | sort | tr '\n' ' '; }

# expect_released <name> — the recipe succeeded and published exactly one tag.
expect_released() {
	local name="$1"
	if ! release; then bad "$name" "recipe refused: $(tail -n1 "$ROOT/out")"; return 1; fi
	local tags; tags="$(remote_tags)"
	[ "$tags" = "$VER " ] || { bad "$name" "remote tags are [$tags], want only $VER"; return 1; }
	[ "$(git ls-remote origin refs/heads/main | cut -f1)" = "$(git rev-parse HEAD)" ] || { bad "$name" "remote main is not the release commit"; return 1; }
	[ "$(cat VERSION)" = "${VER#v}" ] || { bad "$name" "VERSION is $(cat VERSION)"; return 1; }
	ok "$name"
}

# expect_refused <name> — the CHANGELOG guard stopped the recipe before it
# wrote VERSION, committed, tagged or pushed anything.
expect_refused() {
	local name="$1" head; head="$(git rev-parse HEAD)"
	if release; then bad "$name" "recipe released without a real $HEADING section"; return 1; fi
	grep -q 'CHANGELOG.md has no' "$ROOT/out" || { bad "$name" "refused for the wrong reason: $(tail -n1 "$ROOT/out")"; return 1; }
	[ "$(git rev-parse HEAD)" = "$head" ] || { bad "$name" "a commit was made"; return 1; }
	[ "$(cat VERSION)" = 0.0.1-alpha ] || { bad "$name" "VERSION was written"; return 1; }
	[ -z "$(git status --porcelain)" ] || { bad "$name" "working tree was modified"; return 1; }
	! git rev-parse -q --verify "refs/tags/$VER" >/dev/null || { bad "$name" "a local tag was created"; return 1; }
	[ -z "$(remote_tags)" ] || { bad "$name" "a tag reached the remote"; return 1; }
	ok "$name"
}

# Each case runs in its own subshell (its own HOME, clone and remote) and
# reports through its exit status.
pass=0; fail=0; n=0
tally() { if "$@"; then pass=$((pass+1)); else fail=$((fail+1)); fi; }
refused_case()  ( fixture "case$n"; changelog "$2"; expect_refused "$1" )
released_case() ( fixture "case$n"; changelog "$2"; expect_released "$1" )
refuse() { n=$((n+1)); tally refused_case "$@"; }  # refuse <name> <changelog-body>
accept() { n=$((n+1)); tally released_case "$@"; } # accept <name> <changelog-body>

echo "=== push: only the named tag is published ==="
follow_tags() (
	fixture follow-tags
	changelog "$HEADING"
	# After the fixture's own pushes, so only the recipe's push can publish it.
	git tag -a v0.0.9-unrelated -m unrelated HEAD~1
	git config --global push.followTags true
	expect_released "push.followTags=true does not publish an unrelated reachable annotated tag"
)
tally follow_tags

echo "=== CHANGELOG guard: a heading counts only outside a fenced code block ==="
refuse "backtick-fenced heading only" \
	"$(printf 'Example:\n\n%smarkdown\n%s\n%s\n' "$FENCE" "$HEADING" "$FENCE")"
refuse "tilde-fenced heading only" \
	"$(printf '~~~\n%s\n~~~\n' "$HEADING")"
refuse "a shorter fence line does not close a longer fence" \
	"$(printf '%s\n%s\n%s\n%s\n' "$LONG_FENCE" "$FENCE" "$HEADING" "$LONG_FENCE")"
refuse "a tilde line does not close a backtick fence" \
	"$(printf '%s\n~~~\n%s\n%s\n' "$FENCE" "$HEADING" "$FENCE")"
refuse "an unclosed fence runs to the end of the file" \
	"$(printf '%s\n%s\n' "$FENCE" "$HEADING")"
refuse "a fence indented three spaces is still a fence" \
	"$(printf '   %s\n%s\n   %s\n' "$FENCE" "$HEADING" "$FENCE")"
accept "a real heading after a closed fenced example" \
	"$(printf '%smarkdown\n%s\n%s\n\n%s\n' "$FENCE" "$HEADING" "$FENCE" "$HEADING")"
accept "a line indented four spaces is indented code, not a fence" \
	"$(printf '    %s\n\n%s\n' "$FENCE" "$HEADING")"

echo
echo "release-alpha: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
