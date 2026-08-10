# go-firewall test targets.
#
#   make lint                     golangci-lint across every target GOOS
#   make test-general             unit / parser tests — fast, no root, no VM
#   make test-integration-linux   Linux backends end-to-end in a throwaway QEMU VM
#   make test-integration-freebsd pf backend end-to-end in a throwaway FreeBSD VM
#   make test-integration-windows Windows Firewall backend in a throwaway Windows VM
#   make test-integration         every OS's integration (slow; big downloads)
#   make test                     general + every OS's integration
#   make                          build the go-firewall CLI (separate module in ./cmd/go-firewall)
#   make install                  install the go-firewall CLI into $GOBIN
#
# test-general runs the plain `go test` suite (rule parsing/marshalling, capability
# and helper logic) — it never touches a live firewall.
#
# The test-integration* targets boot disposable QEMU VMs and run the capability-
# driven suite against the real backends there, so nothing touches the host:
#   * Linux   — nft/firewalld/ufw/iptables/apf/csf natively in an Ubuntu VM.
#               Limit backends with BACKENDS, e.g. `make test-integration BACKENDS=nft`.
#   * FreeBSD — pf in a FreeBSD VM (pf runs natively; also covers macOS's pf backend).
#   * Windows — the Windows Firewall backend in a Windows VM (heaviest; large image).
# They need qemu-system-x86_64, KVM (/dev/kvm), genisoimage (and python3 for FreeBSD).
#
# macOS is not automatable in a VM (Apple hardware); run its pf backend manually on a
# Mac: `sudo go test -tags integration -run TestIntegration`.
#
# VM artifacts (cloud images, overlay disks, seeds) are cached under ./.cache
# (git-ignored). `make clean` removes that cache and the compiled test binaries.

BACKENDS ?=
CLI_DIR := ./cmd/go-firewall
BUILD_DIR := ./build
CLI_BIN := $(BUILD_DIR)/go-firewall

# Sources the CLI is built from: its own package plus the library it imports.
CLI_SRC := $(shell find $(CLI_DIR) . -maxdepth 1 -name '*.go' -not -name '*_test.go') \
           $(CLI_DIR)/go.mod $(CLI_DIR)/go.sum go.mod go.sum

.PHONY: all lint test test-general test-integration test-integration-linux test-integration-freebsd test-integration-windows cli install clean

# Bare `make` builds the CLI.
.DEFAULT_GOAL := all
all: cli

test: test-general test-integration

# Lint every target GOOS. Each backend is behind a build tag, so a single run
# only sees one platform's code. The linux run is authoritative (it compiles all
# backends and shared helpers, so `unused` is meaningful); the cross-compiled
# runs disable `unused` because a linux-only helper unavoidably reads as dead
# code under another GOOS. Requires golangci-lint v2 (see .golangci.yml).
lint:
	golangci-lint run ./...
	GOOS=darwin  golangci-lint run --disable=unused ./...
	GOOS=freebsd golangci-lint run --disable=unused ./...
	GOOS=windows golangci-lint run --disable=unused ./...
	cd $(CLI_DIR) && golangci-lint run ./...

test-general:
	go test ./...

test-integration: test-integration-linux test-integration-freebsd test-integration-windows

test-integration-linux:
	./test/integration/host-linux-vm.sh $(BACKENDS)

test-integration-freebsd:
	./test/integration/host-freebsd-vm.sh

test-integration-windows:
	./test/integration/host-windows-vm.sh

# Build the go-firewall CLI into $(BUILD_DIR) (./build by default, git-ignored).
# The CLI lives in a separate Go module (so the kong dependency is not imposed
# on library users) and is built from $(CLI_DIR). `cli` is a convenience alias
# for the real binary target below, which only relinks when a source changes.
# Override the version with: make cli VERSION=v1.2.3
cli: $(CLI_BIN)

$(CLI_BIN): $(CLI_SRC) | $(BUILD_DIR)
	go build -C $(CLI_DIR) -ldflags "-X main.version=$(VERSION)" -o $(abspath $(CLI_BIN)) .

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Install the go-firewall CLI into $GOBIN (or $GOPATH/bin). Requires Go 1.26+.
install:
	go install -C $(CLI_DIR) -ldflags "-X main.version=$(VERSION)"

clean:
	rm -rf .cache $(BUILD_DIR) test/integration/firewall.test test/integration/firewall.test.*
