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

.PHONY: lint
lint:
	CGO_ENABLED=0 $(GO) vet $(shell $(GO) list ./... | grep -v /examples/)

.PHONY: test
test: lint $(MODULES:%=%-test)

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

SUBMODULE_TAGS := 

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# SUBMODULE_TAGS lists nested modules tagged in lockstep with the root
# (release-versioning.md P2). deps-latest runs before compiling in a
# consumer repo; release-alpha publishes this repo's next -alpha tag to dev.

.PHONY: release-alpha deps-latest

release-alpha:
	@V=$$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0-alpha); \
	NEXT=$$(echo $$V | awk -F'[.-]' '{printf "v%s.%s.%d-alpha", substr($$1,2), $$2, $$3+1}'); \
	echo $${NEXT#v} > VERSION && git add VERSION && git commit -q -m "chore(release): $$NEXT" || true; \
	git tag $$NEXT; \
	for s in $(SUBMODULE_TAGS); do git tag "$$s/$$NEXT"; done; \
	git push dev HEAD --tags && echo "Tagged $$NEXT"

deps-latest:
	@GOWORK=off sh -c 'SELF=$$(go list -m); for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do go get "$$m@latest" || exit 1; done; go mod tidy'
