#!/bin/sh
# docker-build-integration.sh <dockerfile> <image-tag> <context-dir> builds an integration image, passing GOPRIVATE and GIT_CONFIG_* as the BuildKit secret gomodauth from a 0600 file outside the context.

set -eu

[ "$#" -eq 3 ] || {
	echo "usage: $0 <dockerfile> <image-tag> <context-dir>" >&2
	exit 2
}
dockerfile=$1
image=$2
context=$3
DOCKER=${DOCKER:-docker}

# Prints export NAME='value' with single quotes escaped.
emit() {
	eval "value=\${$1}"
	escaped=$(printf '%s' "$value" | sed "s/'/'\\\\''/g")
	printf "export %s='%s'\n" "$1" "$escaped"
}

# Refuse a staging directory inside the build context before writing anything.
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
