.PHONY: build test clean lint format all

# variables
BINARY_NAME := gh-attest-util
BINARY_DIR := bin

# get github token from gh cli if not set
GH_TOKEN ?= $(shell gh auth token)
export GH_TOKEN

# set policy version if not set
POLICY_VERSION ?= v0.8.0
export POLICY_VERSION

all: format lint test build

build:
	mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/$(BINARY_NAME) .

test:
	go test ./...

lint:
	golangci-lint run

format:
	gofmt -w .

clean:
	rm -rf $(BINARY_DIR)
