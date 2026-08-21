GO ?= go

MODULE_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(MODULE_ROOT)/../..)

.PHONY: test
test: unit

# CGO_ENABLED=0 matches the root Makefile's export and every other module: the
# tree has to test on a machine without libpam0g-dev. The race detector needs
# cgo, so it cannot run here — the root `test-race` target owns race coverage
# for the whole module and is the one place that turns cgo on.
.PHONY: unit
unit:
	@echo "==> Running OTP unit tests..."
	CGO_ENABLED=0 $(GO) test -v -timeout=300s ./...

.PHONY: integration-test
integration-test:
	@echo "==> Running OTP integration tests..."
	CGO_ENABLED=0 $(GO) test -v -timeout=300s -tags=integration $(REPO_ROOT)/test/integration/otp/...

.PHONY: all-tests
all-tests: unit integration-test
	@echo "==> All OTP tests passed!"

.PHONY: coverage
coverage:
	@echo "==> Generating coverage report..."
	$(GO) test -coverprofile=coverage.out ./...
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
	golangci-lint run ./...
