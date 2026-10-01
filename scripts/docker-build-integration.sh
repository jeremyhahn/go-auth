#!/bin/sh
# docker-build-integration.sh — build an integration-suite image, handing the
# private-module credentials to it as a BuildKit secret (go-auth#42).
#
#   docker-build-integration.sh <dockerfile> <image-tag> <context-dir>
#
# go.mod requires github.com/jeremyhahn/go-enclave, whose module path says
# github.com while it is served from a private module host. `docker build`
# inherits none of the calling shell's environment, so a bare build cannot
# resolve it (dependency-resolution.md §6). On Gitea the runner injects
# GOPRIVATE and git's GIT_CONFIG_* override set into every job; this script
# copies exactly those variables into a staging file and passes it as the
# secret `gomodauth`, which each Dockerfile sources for its single
# `go mod download` and nothing else.
#
# The staging file is created with mktemp under $TMPDIR, OUTSIDE the build
# context: every Dockerfile ends with `COPY . .`, so a file inside the tree
# would be baked into a layer. It is mode 0600 and removed on every exit path.
# The token never appears on a command line or in the build log.
#
# With no credentials in the environment the file stays empty and the build
# still runs: the mount is optional, and modules then resolve from whatever
# proxy this machine reaches. That is the shape github.com CI uses.

set -eu

[ "$#" -eq 3 ] || {
	echo "usage: $0 <dockerfile> <image-tag> <context-dir>" >&2
	exit 2
}
dockerfile=$1
image=$2
context=$3
DOCKER=${DOCKER:-docker}

# Prints `export NAME='value'`, with any single quote in the value escaped, so
# sourcing the file can only ever assign the value.
emit() {
	eval "value=\${$1}"
	escaped=$(printf '%s' "$value" | sed "s/'/'\\\\''/g")
	printf "export %s='%s'\n" "$1" "$escaped"
}

# Refuse a staging directory inside the context BEFORE writing anything: a
# credential baked into a layer cannot be taken back by deleting the file.
# Both paths are resolved physically, so a symlink cannot hide the nesting.
stage_dir=$(cd "${TMPDIR:-/tmp}" && pwd -P)
context_dir=$(cd "$context" && pwd -P)
case "$stage_dir/" in
"$context_dir"/*)
	echo "docker-build-integration: TMPDIR ($stage_dir) is inside the build context ($context_dir); credentials staged there would be copied into the image. Point TMPDIR outside the checkout." >&2
	exit 1
	;;
esac

umask 077
stage=$(mktemp "$stage_dir/gomodauth.XXXXXX")
trap 'rm -f "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

count=${GIT_CONFIG_COUNT:-0}
case "$count" in
'' | *[!0-9]*)
	echo "docker-build-integration: GIT_CONFIG_COUNT is not a number" >&2
	exit 2
	;;
esac

if [ "$count" -gt 0 ]; then
	{
		if [ -n "${GOPRIVATE:-}" ]; then
			emit GOPRIVATE
		fi
		emit GIT_CONFIG_COUNT
		i=0
		while [ "$i" -lt "$count" ]; do
			emit "GIT_CONFIG_KEY_$i"
			emit "GIT_CONFIG_VALUE_$i"
			i=$((i + 1))
		done
	} >"$stage"
	echo "docker-build-integration: staged private-module credentials for $image"
else
	echo "docker-build-integration: no private-module credentials in the environment; resolving from the configured proxy"
fi

DOCKER_BUILDKIT=1 "$DOCKER" build \
	--secret "id=gomodauth,src=$stage" \
	-f "$dockerfile" \
	-t "$image" \
	"$context"
