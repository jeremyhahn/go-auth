GO ?= go

MODULE_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(MODULE_ROOT)/../../..)

.PHONY: test
test: unit

.PHONY: unit
unit:
	@echo "==> Running OTP unit tests..."
	$(GO) test -v -race $(REPO_ROOT)/pkg/otp/...

.PHONY: integration-test
integration-test:
	@echo "==> Running OTP integration tests..."
	$(GO) test -v -race -tags=integration $(REPO_ROOT)/test/integration/otp/...

.PHONY: all-tests
all-tests: unit integration-test
	@echo "==> All OTP tests passed!"

.PHONY: coverage
coverage:
	@echo "==> Generating coverage report..."
	$(GO) test -coverprofile=coverage.out $(REPO_ROOT)/pkg/otp/...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: clean
clean:
	$(GO) clean -cache -testcache
	rm -f coverage.out coverage.html
	rm -f *.log *.prof
	@echo "Cleaned build artifacts and test cache"

.PHONY: lint
lint:
	cd $(REPO_ROOT) && golangci-lint run ./pkg/otp/...
