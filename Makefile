GO ?= go

MODULES := secret pam radius tacacs ldap pkcs11 yubikey oauth otp tpm2
MODULE_DIR_secret := pkg/secret
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
# and the target skips; CI installs all of them explicitly.

# CI passes GOSEC_EXTRA="-fmt=sarif -out=gosec.sarif" so the SARIF it uploads
# to code scanning comes from the same flags a developer runs, not a second
# set that can drift (devops.md §4).
GOSEC_EXTRA ?=

.PHONY: gosec
gosec:
	@GOSEC=$$(command -v gosec 2>/dev/null); \
	if [ -n "$$GOSEC" ]; then \
		"$$GOSEC" -exclude-generated -exclude-dir=examples -severity medium -confidence medium $(GOSEC_EXTRA) ./... || exit 1; \
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

# Everything a pull request must pass (devops.md §4). Includes security.
.PHONY: ci
ci: lint build test security

.PHONY: clean
clean:
	go clean -cache -testcache

.PHONY: integration-test
integration-test: $(MODULES:%=%-integration-test)

.PHONY: secret-test
secret-test:
	$(MAKE) -C $(MODULE_DIR_secret) test

.PHONY: secret-integration-test
secret-integration-test:
	$(MAKE) -C $(MODULE_DIR_secret) integration-test

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

SUBMODULE_TAGS := 
# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# SUBMODULE_TAGS lists nested modules tagged in lockstep with the root
# (release-versioning.md P2). deps-latest runs before compiling in a
# consumer repo; release-alpha publishes this repo's next -alpha tag to dev.
# deps-latest picks the highest tag INCLUDING -alpha prereleases — bare
# 'go get @latest' ignores prereleases and would downgrade to legacy v0.0.0.

.PHONY: release-alpha deps-latest

release-alpha:
	@V=$$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0-alpha); \
	NEXT=$$(echo $$V | awk -F'[.-]' '{printf "v%s.%s.%d-alpha", substr($$1,2), $$2, $$3+1}'); \
	echo $${NEXT#v} > VERSION && git add VERSION && git commit -q -m "chore(release): $$NEXT" || true; \
	git tag $$NEXT; \
	for s in $(SUBMODULE_TAGS); do git tag "$$s/$$NEXT"; done; \
	git push dev HEAD --tags && echo "Tagged $$NEXT"

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
