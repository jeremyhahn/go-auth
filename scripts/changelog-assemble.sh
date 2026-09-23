#!/bin/sh
# changelog-assemble.sh — fold changelog.d/ fragments into CHANGELOG.md as the
# section of the release being cut (go-auth#22; release-versioning.md §5).
#
#   changelog-assemble.sh <X.Y.Z-alpha>     (unprefixed, as in VERSION)
#
# Run from the repository root by `make release-changelog`, which is a
# prerequisite of `make release-alpha` and commits the result before the tag
# is cut. The script only edits the working tree; it never runs git.
#
# What it does, when there is something to release:
#   - inserts "## [<version>] - <UTC date>" directly under "## [Unreleased]";
#   - moves whatever "## [Unreleased]" already held into that section (the
#     §5 migration: pre-fragment Unreleased content releases normally);
#   - appends each fragment, in issue-number order, merging entries under the
#     same "### <subsection>" heading so the section has one "### Fixed", not
#     one per fragment, and collecting link definitions ("[#22]: <url>") once
#     at the end of the section;
#   - deletes each fragment it folded in. changelog.d/.gitkeep stays.
#
# It changes nothing, and exits 0, when there is nothing to fold in: no
# fragments and an empty Unreleased section, or a section for <version> that
# already exists (a re-run after the assembly was committed). The release
# recipe's own CHANGELOG guard then decides whether the release may proceed.
#
# It refuses — exit 1, CHANGELOG.md and changelog.d/ untouched — when folding
# in would lose or misplace an entry: fragments present but the version's
# section already exists (they would be stranded), no "## [Unreleased]"
# heading to insert under, a fragment that is not <issue>-<slug>.md, or a
# fragment carrying a "#" or "##" heading of its own, or a fenced code block
# left open at the end of a fragment or of CHANGELOG.md.
#
# Fenced code blocks (``` or ~~~, CommonMark rules) are content, not
# structure: a "# comment" or "### Added" line inside one is neither a heading
# nor a section boundary, a "[x]: y" line inside one is not a link
# definition, and the block is carried over verbatim.

set -eu

fail() {
	printf 'changelog-assemble: %s\n' "$*" >&2
	exit 1
}

[ "$#" -eq 1 ] || fail 'usage: changelog-assemble.sh <X.Y.Z-alpha>'
ver=$1
printf '%s' "$ver" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$' ||
	fail "version is not of the form X.Y.Z-alpha (unprefixed): $ver"

cl=CHANGELOG.md
dir=changelog.d
[ -f "$cl" ] || fail "no $cl in $(pwd)"

# Fragments, in issue-number order. Anything else in changelog.d/ is refused
# rather than skipped: a misnamed fragment would otherwise never be released.
frags=''
if [ -d "$dir" ]; then
	for name in $(ls -A "$dir" | LC_ALL=C sort -t- -k1,1n -k2); do
		[ "$name" = .gitkeep ] && continue
		printf '%s' "$name" | grep -Eq '^[1-9][0-9]*-[A-Za-z0-9._-]+\.md$' ||
			fail "$dir/$name is not an <issue>-<slug>.md fragment; rename or remove it"
		[ -f "$dir/$name" ] || fail "$dir/$name is not a regular file"
		frags="$frags $dir/$name"
	done
fi

# fence_awk is awk shared by both passes. fenced(line) reports whether line
# belongs to a fenced code block — its opening fence, its content, or its
# closing fence — and tracks the open fence in infence/fch/flen. Written
# without regex intervals so mawk, gawk and busybox awk all accept it.
fence_awk='
function fence_run(s,   c, k) {
	c = substr(s, 1, 1)
	for (k = 1; substr(s, k + 1, 1) == c; k++) ;
	return k
}
function fenced(line,   s, k) {
	s = line
	sub(/^ ? ? ?/, "", s)
	if (!infence) {
		if (s !~ /^(```|~~~)/) return 0
		k = fence_run(s)
		if (substr(s, 1, 1) == "`" && index(substr(s, k + 1), "`")) return 0
		infence = 1; fch = substr(s, 1, 1); flen = k
		return 1
	}
	if (substr(s, 1, 1) == fch) {
		k = fence_run(s)
		if (k >= flen && substr(s, k + 1) ~ /^[ \t]*$/) infence = 0
	}
	return 1
}
'

has_line_prefix() { # has_line_prefix <prefix> — a line of $cl, outside fenced code, starts with it
	awk -v p="$1" "$fence_awk"'
fenced($0) { next }
index($0, p) == 1 { f = 1; exit }
END { exit f ? 0 : 1 }' "$cl"
}

if has_line_prefix "## [$ver]"; then
	[ -z "$frags" ] || fail "$cl already has a ## [$ver] section, but changelog.d/ still holds:$frags — they would be stranded"
	echo "changelog-assemble: ## [$ver] already present, nothing to fold in"
	exit 0
fi
if ! has_line_prefix '## [Unreleased]'; then
	[ -z "$frags" ] || fail "$cl has no ## [Unreleased] heading to assemble$frags under"
	echo "changelog-assemble: no fragments and no Unreleased section, nothing to fold in"
	exit 0
fi

date=$(date -u +%Y-%m-%d)
tmp="$cl.assemble.$$"
trap 'rm -f "$tmp"' EXIT

# shellcheck disable=SC2086 # $frags is a word list of validated file names.
awk -v ver="$ver" -v date="$date" -v cl="$cl" "$fence_awk"'
# trim drops the blank lines around a chunk; the inside, fenced code
# included, is kept verbatim.
function trim(s) {
	sub(/^\n+/, "", s); sub(/\n+$/, "", s); return s
}
# flush appends the chunk read since the last heading or file boundary,
# trimmed, so chunks from different sources join into one tight list.
function flush(   c) {
	c = trim(buf); buf = ""
	if (c == "") return
	if (cur == "") pre = pre (pre == "" ? "" : "\n") c
	else body[cur] = body[cur] (body[cur] == "" ? "" : "\n") c
}
function feed(line) {
	if (fenced(line)) { buf = buf line "\n"; return }
	if (line ~ /^### /) {
		flush()
		cur = line
		if (!(cur in seen)) { seen[cur] = 1; order[++n] = cur }
		return
	}
	if (line ~ /^\[[^]]+\]: /) {
		if (!(line in isref)) { isref[line] = 1; refs[++nr] = line }
		return
	}
	buf = buf line "\n"
}
function unclosed(file) {
	printf "changelog-assemble: %s leaves a fenced code block open\n", file > "/dev/stderr"
	bad = 1; exit 1
}
FNR == 1 && NR > 1 && infence { unclosed(prev) }
{ prev = FILENAME }
FILENAME == cl {
	if (state == 0) {
		head = head $0 "\n"
		if (!fenced($0) && index($0, "## [Unreleased]") == 1) state = 1
		next
	}
	if (state == 1 && !infence && $0 ~ /^## /) { flush(); state = 2 }
	if (state == 1) { feed($0); next }
	fenced($0)
	tail = tail $0 "\n"
	next
}
FNR == 1 { flush(); cur = "" }
!infence && /^##? / {
	printf "changelog-assemble: %s carries its own \"%s\" heading; a fragment holds only ### subsections\n", FILENAME, $0 > "/dev/stderr"
	bad = 1; exit 1
}
{ feed($0) }
END {
	if (bad) exit 1
	if (infence) unclosed(prev)
	flush()
	out = trim(pre)
	for (i = 1; i <= n; i++) {
		b = trim(body[order[i]])
		if (b == "") continue
		out = out (out == "" ? "" : "\n\n") order[i] "\n\n" b
	}
	if (out == "") { empty = 1; exit 0 }
	for (i = 1; i <= nr; i++) r = r refs[i] "\n"
	if (r != "") out = out "\n\n" trim(r)
	printf "%s\n## [%s] - %s\n\n%s\n", head, ver, date, out
	if (tail != "") printf "\n%s", tail
}' "$cl" $frags >"$tmp"

if [ ! -s "$tmp" ]; then
	[ -z "$frags" ] || fail "fragments$frags hold no entries"
	echo "changelog-assemble: no fragments and an empty Unreleased section, nothing to fold in"
	exit 0
fi

mv "$tmp" "$cl"
trap - EXIT
count=0
for f in $frags; do
	rm -f "$f"
	count=$((count + 1))
done
echo "changelog-assemble: ## [$ver] assembled from Unreleased and $count fragment(s)"
