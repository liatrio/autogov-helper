.PHONY: build test clean lint generate all

all: lint test build

build: generate
	mkdir -p bin
	go build -o bin/gh-attest-util .

test: generate
	go test ./...

lint: generate
	golangci-lint run

generate:
	cd internal/attestation/schema/gen && go run generate.go

clean:
	rm -rf bin/
	rm -rf internal/attestation/schema/generated/