GO ?= go
DOCKER ?= docker
INTEGRATION_IMAGE ?= go-auth-pkcs11-integration:latest

MODULE_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(MODULE_ROOT)/../../..)

.PHONY: test
test: unit

.PHONY: unit
unit:
	CGO_ENABLED=0 $(GO) test $(REPO_ROOT)/pkg/pkcs11/...

.PHONY: coverage
coverage:
	CGO_ENABLED=0 $(GO) test -coverprofile=coverage.out $(REPO_ROOT)/pkg/pkcs11/...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: integration-test
integration-test:
	$(DOCKER) build -f $(MODULE_ROOT)Dockerfile -t $(INTEGRATION_IMAGE) $(REPO_ROOT)
	$(DOCKER) run --rm $(INTEGRATION_IMAGE)

.PHONY: clean
clean:
	$(GO) clean -cache -testcache
	rm -f coverage.out coverage.html
	rm -f *.log *.prof
	@echo "Cleaned build artifacts and test cache"
