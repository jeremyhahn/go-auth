GO ?= go

.PHONY: test
test: unit

.PHONY: unit
unit:
	CGO_ENABLED=0 $(GO) test ./...

.PHONY: coverage
coverage:
	CGO_ENABLED=0 $(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: integration-test
integration-test:
	CGO_ENABLED=0 $(GO) test -tags integration ./...

.PHONY: clean
clean:
	$(GO) clean -cache -testcache
	rm -f coverage.out coverage.html
	rm -f *.log *.prof
	@echo "Cleaned build artifacts and test cache"
