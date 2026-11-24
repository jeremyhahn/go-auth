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

# CGO_ENABLED=0 so the module builds without libpam headers; CI's race-detector job installs libpam0g-dev and drops it.
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

# actionlint checks the workflows themselves: Actions syntax, expressions and
# runner labels, before CI reads them (devops.md §4, the `make lint` row). It
# picks up .github/actionlint.yaml on its own if the repository adds one to
# declare self-hosted runner labels. actionlint delegates every SC* rule to
# shellcheck and, with shellcheck absent, disables those rules and still exits
# 0, so the target requires both rather than passing with half the checks off.
# Neither tool is installed here (devops.md §4: a make target does not mutate
# the developer's machine); CI's lint job installs both before `make lint`.
.PHONY: actionlint
actionlint:
	@if ! command -v actionlint >/dev/null 2>&1; then \
		echo "actionlint is not installed: the workflows cannot be checked" >&2; \
		echo "  Install: go install github.com/rhysd/actionlint/cmd/actionlint@latest" >&2; \
		exit 1; \
	fi
	@if ! command -v shellcheck >/dev/null 2>&1; then \
		echo "shellcheck is not installed: actionlint would skip every run: script check" >&2; \
		echo "  Install: scripts/install-shellcheck.sh \"\$$(go env GOPATH)/bin\"" >&2; \
		exit 1; \
	fi
	actionlint

.PHONY: lint
lint: fmt-check actionlint
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

# make security: gosec (no -exclude; md5/sha1 uses are annotated with their RFC), govulncheck, go mod verify and trivy fs, all blocking. Tools are not installed here.

# CI passes GOSEC_EXTRA for SARIF output so it runs the same flags as a developer.
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

# trivy-fs fails when trivy is absent, unlike gosec and govulncheck above,
# which CI guards with verify-security-tools. A skip that exits 0 let
# `make security` pass with no filesystem scan at all (go-auth#66).
.PHONY: trivy-fs
trivy-fs:
	@if ! command -v trivy >/dev/null 2>&1; then \
		echo "trivy is not installed: the filesystem scan cannot run" >&2; \
		echo "  Install: https://github.com/aquasecurity/trivy/releases (the release tarball for your platform)" >&2; \
		exit 1; \
	fi
	trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 .

.PHONY: security
security: gosec govulncheck mod-verify trivy-fs

# golangci-lint pin: moves with the go directive and must equal the ci-runner image version; test/ci checks it against go.mod.
GOLANGCI_LINT_VERSION := 2.14.0

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

# Builds never resolve through a workspace.
export GOWORK=off

# deps-latest picks the highest tag including -alpha prereleases, which go get @latest ignores.

# release-alpha: mk/release-alpha.mk is the unmodified handbook template; run make release-alpha VERSION=vX.Y.Z-alpha. AGENT_GIT must be simply expanded.
ifeq ($(origin AGENT_GIT),undefined)
AGENT_GIT := $(shell command -v agent-git.sh 2>/dev/null)
endif
REPO_NAME ?= go-auth
RELEASE_REMOTE ?= origin
include mk/release-alpha.mk

# release-changelog folds changelog.d/ into CHANGELOG.md and commits it before release-alpha tags; it applies the template's guards and is a no-op when there is nothing to fold.
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
