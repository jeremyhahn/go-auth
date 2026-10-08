#!/bin/sh
# verify-ci-tools.sh — fail closed when a CI analyser is not the one the gate
# expects (go-auth#26).
#
#   verify-ci-tools.sh lint <golangci-lint version>
#   verify-ci-tools.sh security
#
# The ci-runner image bakes golangci-lint, gosec and govulncheck. This script
# checks them; it never installs anything. A missing or mismatched tool means
# the image is wrong, and installing over it would hide exactly that. The make
# targets that run the analysers skip a missing tool with exit 0, so without
# this check a runner without the tools would pass with nothing analysed.
#
# Only shell builtins are used besides the tools under test, so the script
# behaves the same with a PATH that holds nothing else (the tests rely on it).

set -u

fail() {
	printf 'verify-ci-tools: %s\n' "$*" >&2
	exit 1
}

require() {
	command -v "$1" >/dev/null 2>&1 ||
		fail "$1 is not on PATH: the runner image is missing its baked copy"
}

verify_lint() {
	want=${1#v}
	[ -n "$want" ] || fail "no golangci-lint version given"
	require golangci-lint
	got=$(golangci-lint version 2>&1) ||
		fail "'golangci-lint version' failed: $got"
	printf '%s\n' "$got"
	# The trailing space keeps 2.14.0 from matching 2.14.00.
	case "$got" in
	*"has version $want "* | *"has version v$want "*) ;;
	*) fail "golangci-lint is not version $want: move the pin and the runner image together" ;;
	esac
}

verify_security() {
	require gosec
	require govulncheck
	# `gosec --version` prints "dev" for any go-installed build, so the image's
	# record is the only statement of which gosec ran.
	tools_file=${CI_RUNNER_TOOLS_FILE:-/etc/ci-runner-tools.txt}
	if [ -r "$tools_file" ]; then
		while IFS= read -r line || [ -n "$line" ]; do
			printf '%s\n' "$line"
		done <"$tools_file"
	fi
	govulncheck -version || fail "'govulncheck -version' failed"
}

case "${1:-}" in
lint) verify_lint "${2:-}" ;;
security) verify_security ;;
*) fail "usage: verify-ci-tools.sh lint <version> | security" ;;
esac
