GO ?= go

.PHONY: test
test: unit

.PHONY: unit
unit:
	@echo "==> Running protected-memory (secret) unit tests..."
	$(GO) test -v -race ./...

# The package has no service to talk to, so there is nothing to integrate
# against; the target exists so the root Makefile can treat every module the
# same way.
.PHONY: integration-test
integration-test:
	@echo "==> No integration tests for the secret package"

.PHONY: all-tests
all-tests: unit integration-test
	@echo "==> All secret tests passed!"

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
