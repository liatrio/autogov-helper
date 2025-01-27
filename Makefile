.PHONY: build test clean lint generate format all

# variables
BINARY_NAME := gh-attest-util
BINARY_DIR := bin
GENERATED_DIR := internal/attestation/schema/generated

# get github token from gh cli if not set
GH_TOKEN ?= $(shell gh auth token)
export GH_TOKEN

all: format lint test build

build: generate
	mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/$(BINARY_NAME) .

test: generate
	go test ./...

lint: generate
	golangci-lint run

format:
	gofmt -w .

generate:
	go generate ./...

clean:
	rm -rf $(BINARY_DIR)
	rm -rf $(GENERATED_DIR)
