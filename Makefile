.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test ./... -v

.PHONY: build
build:
	go build -o gh-attest-util