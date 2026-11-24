#!/bin/sh
# verify-ci-tools.sh lint <version> | security: fail when an analyser baked into the CI image is missing or not the pinned version; never installs.

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
