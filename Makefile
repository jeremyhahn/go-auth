GO ?= go

MODULES := pam radius tacacs ldap pkcs11 yubikey oauth otp tpm2
MODULE_DIR_pam := pkg/pam
MODULE_DIR_radius := pkg/radius
MODULE_DIR_tacacs := pkg/tacacs
MODULE_DIR_ldap := pkg/ldap
MODULE_DIR_pkcs11 := pkg/pkcs11
MODULE_DIR_yubikey := pkg/yubikey
MODULE_DIR_oauth := pkg/oauth
MODULE_DIR_otp := pkg/otp
MODULE_DIR_tpm2 := pkg/tpm2

.PHONY: all
all: test

# pkg/pam splits its default SessionOpener across a //go:build cgo file that
# needs libpam headers. Everything below builds with CGO_ENABLED=0 so the
# module compiles, tests, lints and scans on a machine that does not have
# libpam0g-dev installed. CI's unit-test job is the one exception: the race
# detector requires cgo, so that job installs libpam0g-dev and drops the flag.
export CGO_ENABLED = 0

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: fmt-check
fmt-check:
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "Files not formatted (run 'make fmt'):"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi

.PHONY: lint
lint: fmt-check
	$(GO) vet $(shell $(GO) list ./... | grep -v /examples/)
	@LINTER=$$(command -v golangci-lint 2>/dev/null); \
	if [ -n "$$LINTER" ]; then \
		"$$LINTER" run --timeout=5m ./... || exit 1; \
	else \
		echo "golangci-lint not installed, skipping the umbrella run"; \
		echo "  Install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
		echo "  CI installs it unconditionally, so .golangci.yml still gates every push."; \
	fi

.PHONY: build
build:
	$(GO) build ./...

.PHONY: test
test: lint $(MODULES:%=%-test)

# The race detector requires cgo, and cgo in this module requires libpam
# headers (pkg/pam). Install libpam0g-dev to run this locally; CI's unit-test
# job does exactly that. `make test` stays CGO-free so it runs everywhere.
.PHONY: test-race
test-race:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

# ---- devops.md §8: the mandatory security-analysis suite ----
#
# `make security` is the contract (devops.md §4): CI runs this same target, so
# a finding here is the finding that blocks a merge. The suite is gosec,
# govulncheck, `go mod verify` and `trivy fs`, all blocking.
#
# gosec deliberately runs with NO -exclude rules. The two weak-primitive
# findings this repository carries are protocol constraints, not cipher
# choices, and each is annotated at the import that causes it with the RFC
# that mandates it:
#   G501 crypto/md5  — pkg/radius: the RADIUS Message-Authenticator attribute
#                      is defined as HMAC-MD5 (RFC 2869 §5.14, RFC 3579 §3.2).
#   G505 crypto/sha1 — pkg/yubikey: the Yubico Validation Protocol 2.0 signs
#                      every request and response with HMAC-SHA1.
# Both are HMAC constructions, never bare hashes. A blanket -exclude would hide
# the next crypto/md5 import somewhere it is not justified; a line annotation
# cannot. -exclude-dir=examples drops the //go:build ignore documentation
# snippets, which are not part of the module build.
#
# The tools are not installed by these targets — devops.md §4 forbids a make
# target mutating the developer's machine. A missing tool prints how to get it
# and the target skips. CI does not install them either: it uses the copies
# baked into the ci-runner image and runs verify-security-tools first, which
# fails when one is absent, so a skip cannot turn the gate green (go-auth#26).

# CI passes GOSEC_EXTRA="-fmt=sarif -out=gosec.sarif" so the SARIF it uploads
# to code scanning comes from the same flags a developer runs, not a second
# set that can drift (devops.md §4).
GOSEC_EXTRA ?=

.PHONY: gosec
gosec:
	@GOSEC=$$(command -v gosec 2>/dev/null); \
	if [ -n "$$GOSEC" ]; then \
		"$$GOSEC" -concurrency 4 -exclude-generated -exclude-dir=examples -severity medium -confidence medium $(GOSEC_EXTRA) ./... || exit 1; \
	else \
		echo "gosec not installed, skipping"; \
		echo "  Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

.PHONY: govulncheck
govulncheck:
	@GOVULN=$$(command -v govulncheck 2>/dev/null); \
	if [ -n "$$GOVULN" ]; then \
		"$$GOVULN" ./... || exit 1; \
	else \
		echo "govulncheck not installed, skipping"; \
		echo "  Install: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

.PHONY: mod-verify
mod-verify:
	$(GO) mod verify

.PHONY: trivy-fs
trivy-fs:
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 . || exit 1; \
	else \
		echo "trivy not installed, skipping filesystem scan"; \
		echo "  Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"; \
		echo "  CI installs trivy unconditionally, so this scan still gates every push."; \
	fi

.PHONY: security
security: gosec govulncheck mod-verify trivy-fs

# ---- CI tool verification (go-auth#26) ----
#
# The golangci-lint this gate is judged by. It moves in the SAME change as the
# go directive, never ahead of or behind it: v2.12.2 cannot lint Go 1.27, and
# v2.13.x was measured to panic on Go 1.26 (nilness "unhandled builtin
# recover"). Documented pin (devops.md §9, the "pin specifically documented,
# in place, with the reason" clause). It must equal the version baked into the
# ci-runner image; verify-lint-tool fails on any other version rather than
# installing over it. test/ci checks this pin against go.mod.
GOLANGCI_LINT_VERSION := 2.13.2

.PHONY: print-golangci-lint-version
print-golangci-lint-version:
	@echo $(GOLANGCI_LINT_VERSION)

# Fail closed if golangci-lint is absent or not the pinned version. Never
# installs; see scripts/verify-ci-tools.sh.
.PHONY: verify-lint-tool
verify-lint-tool:
	@$(SHELL) scripts/verify-ci-tools.sh lint $(GOLANGCI_LINT_VERSION)

# Fail closed if gosec or govulncheck is absent, and log the versions that ran.
.PHONY: verify-security-tools
verify-security-tools:
	@$(SHELL) scripts/verify-ci-tools.sh security

# Everything a pull request must pass (devops.md §4). Includes security.
.PHONY: ci
ci: lint build test security

.PHONY: clean
clean:
	go clean -cache -testcache

.PHONY: integration-test
integration-test: $(MODULES:%=%-integration-test)

.PHONY: pam-test
pam-test:
	$(MAKE) -C $(MODULE_DIR_pam) test

.PHONY: pam-integration-test
pam-integration-test:
	$(MAKE) -C $(MODULE_DIR_pam) integration-test

.PHONY: radius-test
radius-test:
	$(MAKE) -C $(MODULE_DIR_radius) test

.PHONY: radius-integration-test
radius-integration-test:
	$(MAKE) -C $(MODULE_DIR_radius) integration-test

.PHONY: tacacs-test
tacacs-test:
	$(MAKE) -C $(MODULE_DIR_tacacs) test

.PHONY: tacacs-integration-test
tacacs-integration-test:
	$(MAKE) -C $(MODULE_DIR_tacacs) integration-test

.PHONY: ldap-test
ldap-test:
	$(MAKE) -C $(MODULE_DIR_ldap) test

.PHONY: ldap-integration-test
ldap-integration-test:
	$(MAKE) -C $(MODULE_DIR_ldap) integration-test

.PHONY: pkcs11-test
pkcs11-test:
	$(MAKE) -C $(MODULE_DIR_pkcs11) test

.PHONY: pkcs11-integration-test
pkcs11-integration-test:
	$(MAKE) -C $(MODULE_DIR_pkcs11) integration-test

.PHONY: yubikey-test
yubikey-test:
	$(MAKE) -C $(MODULE_DIR_yubikey) test

.PHONY: yubikey-integration-test
yubikey-integration-test:
	$(MAKE) -C $(MODULE_DIR_yubikey) integration-test

.PHONY: oauth-test
oauth-test:
	$(MAKE) -C $(MODULE_DIR_oauth) test

.PHONY: oauth-integration-test
oauth-integration-test:
	$(MAKE) -C $(MODULE_DIR_oauth) integration-test

.PHONY: otp-test
otp-test:
	$(MAKE) -C $(MODULE_DIR_otp) test

.PHONY: otp-integration-test
otp-integration-test:
	$(MAKE) -C $(MODULE_DIR_otp) integration-test

.PHONY: tpm2-test
tpm2-test:
	$(MAKE) -C $(MODULE_DIR_tpm2) test

.PHONY: tpm2-integration-test
tpm2-integration-test:
	$(MAKE) -C $(MODULE_DIR_tpm2) integration-test

# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# deps-latest runs before compiling in a consumer repo. It picks the highest
# tag INCLUDING -alpha prereleases — bare 'go get @latest' ignores
# prereleases and would downgrade to legacy v0.0.0.

# ---- release-alpha: handbook template v2.3.9 (go-auth#22) ----
# mk/release-alpha.mk is software/templates/make/release-alpha.mk from the
# handbook, vendored UNMODIFIED with its regression harness
# (mk/testdata/release-alpha-tests.sh); read its header before changing
# anything here. Cut a release with an explicit version — the recipe refuses
# to guess patch/minor/major (release-versioning.md):
#   make release-alpha VERSION=vX.Y.Z-alpha
# It first runs release-changelog (below), which folds changelog.d/ into
# CHANGELOG.md and commits that, so the template's CHANGELOG guard finds the
# section and the tag carries it.
# Every git write goes through agent-git.sh (identity + signing as
# agent-go-auth), the tag is annotated, and only that tag and the release
# commit are pushed. go-auth is a single module, so there are no nested-module
# lockstep tags. AGENT_GIT resolves from PATH — never bake an absolute path
# (template v2.3.6); an unresolved value fails before VERSION is written.
# It must be SIMPLY expanded: the template reads $(value AGENT_GIT), which
# for a recursive `?=` is the unexpanded $(shell ...) text, not a path. A
# bare `agent-git.sh` would not do either — `test -x` does not search PATH.
ifeq ($(origin AGENT_GIT),undefined)
AGENT_GIT := $(shell command -v agent-git.sh 2>/dev/null)
endif
REPO_NAME ?= go-auth
RELEASE_REMOTE ?= origin
include mk/release-alpha.mk

# ---- release-changelog: fold changelog.d/ into CHANGELOG.md (go-auth#22) ----
# release-versioning.md §5: a PR adds changelog.d/<issue>-<slug>.md and never
# edits CHANGELOG.md; the release step assembles the fragments into the new
# version's section, deletes them, and COMMITS that before tagging. This target
# is a prerequisite of release-alpha, so the tagged commit always carries the
# assembled section. It adds no prerequisite to the template itself, which
# stays unmodified.
#
# It takes its inputs the same way the template does — `override export` of
# $(value ...) with the public and internal names unexported — so it opens no
# command-line injection path the template closed (see the template's v2.3.3,
# v2.3.7 and v2.3.8 notes); the body references only $$REL_* shell
# parameters. Every guard that can refuse the release without touching the
# network or the tree runs here too, and the remote duplicate-tag check with
# the same exit-code reading, so a release the template would refuse leaves no
# local assembly commit behind. The remaining gap is the template's own: a
# push that fails after the commit.
#
# With no fragments and an empty Unreleased section, or with the version's
# section already present (a re-run), it changes and commits nothing, and the
# template's CHANGELOG guard decides.
.PHONY: release-changelog
release-alpha: release-changelog
release-changelog: override export REL_VERSION   := $(value VERSION)
release-changelog: override export REL_REMOTE    := $(value RELEASE_REMOTE)
release-changelog: override export REL_REPO      := $(value REPO_NAME)
release-changelog: override export REL_AGENT_GIT := $(value AGENT_GIT)
release-changelog:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z-alpha (no leading zeroes): $$REL_VERSION"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "ERROR: releases are cut from main; you are on $$(git rev-parse --abbrev-ref HEAD)."; exit 1; }
	@test -n "$$REL_REPO" || { echo 'ERROR: REPO_NAME is empty — set it to the literal repo name in the Makefile'; exit 1; }
	@test -x "$$REL_AGENT_GIT" || { echo 'ERROR: AGENT_GIT does not point at an executable agent-git.sh — every git write in this recipe signs through it, and a bad path must fail before CHANGELOG.md is assembled'; exit 1; }
	@test -n "$$REL_REMOTE" || { echo 'ERROR: RELEASE_REMOTE is empty — set it to the Gitea remote'; exit 1; }
	@git remote get-url "$$REL_REMOTE" >/dev/null 2>&1 || { echo "ERROR: no git remote named $$REL_REMOTE. Set RELEASE_REMOTE to the Gitea remote"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/$$REL_VERSION" >/dev/null || { echo "ERROR: tag $$REL_VERSION already exists locally"; exit 1; }
	@rc=0; git ls-remote --exit-code --tags "$$REL_REMOTE" "refs/tags/$$REL_VERSION" >/dev/null 2>&1 || rc=$$?; \
	case "$$rc" in \
	  0) echo "ERROR: tag $$REL_VERSION already exists on $$REL_REMOTE"; exit 1 ;; \
	  2) : ;; \
	  *) echo "ERROR: could not reach $$REL_REMOTE to check whether tag $$REL_VERSION exists. Refusing to continue: an unreachable remote is not an absent tag"; exit 1 ;; \
	esac
	@test -z "$$(git status --porcelain)" || { echo 'ERROR: working tree not clean'; exit 1; }
	@sh scripts/changelog-assemble.sh "$${REL_VERSION#v}"
	@if [ -n "$$(git status --porcelain)" ]; then \
	  "$$REL_AGENT_GIT" "$$REL_REPO" add -A -- CHANGELOG.md changelog.d && \
	  "$$REL_AGENT_GIT" "$$REL_REPO" commit -m "docs(changelog): assemble $$REL_VERSION"; \
	fi

.PHONY: deps-latest

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
