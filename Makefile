.PHONY: build test clean lint all

all: lint test build

build:
	mkdir -p bin
	go build -o bin/gh-attest-util ./cmd/gh-attest-util

test:
	go test ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/