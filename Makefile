# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

.PHONY: all lint lint-fix vet gosec govulncheck glossary glossary-check check-doc-links check-site site site-serve site-clean build build-linux-amd64 build-linux-amd64-debug build-linux-arm64 build-linux-arm64-debug build-linux-riscv64 build-linux-riscv64-debug coverage test test-integration test-e2e fuzz doc notices image image-from-source release release-local-test get-ldflags check-version clean

all: build-linux-amd64 build-linux-arm64 build-linux-riscv64

# Project name
PROJECT_NAME := k8s-kms-plugin
GO_MODULE_NAME := "github.com/eclipse-keysealer/$(PROJECT_NAME)"
BINARY_NAME = $(PROJECT_NAME)

# Useful variables for build metadata
#
# SECURITY: every value below is interpolated into shell recipes (ldflags, file
# names, image tags), so it must never contain shell metacharacters. VERSION in
# particular is attacker-influenced: anyone who can create a git tag controls
# its content, and git allows shell metacharacters (backticks, $(), ;, |, &,
# quotes, ...) in tag names. The raw git output is therefore sanitized inside a
# single shell invocation — it never becomes a make variable, so make can never
# re-expand attacker content as $(...) syntax — and reduced to the strict
# [A-Za-z0-9._+-] character set that is safe in shell commands, file names and
# -ldflags values. A warning is printed if any character had to be stripped.
VERSION ?= $(shell \
	raw="$$(git describe --tags --always --dirty 2>/dev/null)"; \
	[ -n "$$raw" ] || raw="unknown"; \
	safe="$$(printf '%s' "$$raw" | tr -cd 'A-Za-z0-9._+-')"; \
	[ -n "$$safe" ] || safe="unknown"; \
	[ "$$safe" = "$$raw" ] || echo "make: warning: git tag [$$raw] contains characters unsafe for build metadata; using [$$safe]" >&2; \
	printf '%s' "$$safe" \
)
# equivalent command to test git dirty status in bash terminal: [[ -n "$(git status --porcelain)" ]] && echo "true" || echo "false"
IS_GIT_DIRTY := $(shell [ -n "$$(git status --porcelain)" ] && echo "true" || echo "false")
# Commit hashes are hex by construction, but they are git-controlled and flow
# into the same -ldflags, so they are sanitized too (defense in depth).
COMMIT_LONG ?= $(shell git rev-parse HEAD 2>/dev/null | tr -cd 'A-Za-z0-9')
COMMIT_SHORT ?= $(shell git rev-parse --short=8 HEAD 2>/dev/null | tr -cd 'A-Za-z0-9')
# %cI is a normalized ISO-8601 timestamp; keep only its safe characters.
COMMIT_TIMESTAMP := $(shell git show -s --format=%cI HEAD 2>/dev/null | tr -cd 'A-Za-z0-9._+-:')
# The remaining values come from trusted local commands (go, uname, date) and
# are safe by construction. GO_VERSION intentionally contains spaces, which are
# preserved inside the single-quoted -X values.
GO_VERSION ?= $(shell go version)
BUILD_PLATFORM  ?= $(shell uname -m)
BUILD_DATE ?= $(shell date -u --iso-8601=seconds)

# Go Flags
GIT_INFO_LDFLAGS = -X '$(GO_MODULE_NAME)/pkg/version.RawGitDescribe=$(VERSION)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitIDLong=$(COMMIT_LONG)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitIDShort=$(COMMIT_SHORT)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GoVersion=$(GO_VERSION)' \
	-X '$(GO_MODULE_NAME)/pkg/version.BuildPlatform=$(BUILD_PLATFORM)' \
	-X '$(GO_MODULE_NAME)/pkg/version.BuildDate=$(BUILD_DATE)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitTimestamp=$(COMMIT_TIMESTAMP)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitDirtyStr=$(IS_GIT_DIRTY)'

# Go build parameters
CGO_ENABLED := 1
DIST_DIR := dist
# Cross-compilers
LINUX_AMD64_GCC := gcc
LINUX_ARM64_GCC := aarch64-linux-gnu-gcc
LINUX_RISCV64_GCC := riscv64-linux-gnu-gcc

## Tool preconditions
# $(call require,<binary>,<how to install it>) — fail early with an install hint.
#
# Probes by running the tool, not `command -v`: a goenv shim stays on PATH even
# when the tool is not installed for the active Go version, so `command -v` says
# yes and the build dies later. Exit 127 (missing binary or dead shim) is the
# only status treated as missing; tools without --version exit 1 or 2 and pass.
#
# A hint must not contain a comma — make would read it as another $(call) argument.
define require
@$(1) --version >/dev/null 2>&1; \
if [ $$? -eq 127 ]; then \
    echo "$(1) not found. Install it with:"; \
    echo "  $(2)"; \
    exit 1; \
fi
endef

# Debian/Ubuntu package names, matching the CI runner (setup-build-env).
CC_INSTALL_HINT := sudo apt-get install build-essential
ARM64_CC_INSTALL_HINT := sudo apt-get install gcc-aarch64-linux-gnu libc6-dev-arm64-cross
RISCV64_CC_INSTALL_HINT := sudo apt-get install gcc-riscv64-linux-gnu libc6-dev-riscv64-cross

## Licenses
# go-licenses renders go-licenses.tpl, which cannot pad the table cells to a
# common width, so the raw output is piped through align-md-tables.awk.
#
# Both stages write to temp files and NOTICES.md is only replaced once the whole
# chain has succeeded. Writing into it directly would truncate the committed file
# the moment either stage fails — and go-licenses does fail, e.g. against Go 1.26
# (google/go-licenses#128) — leaving an empty NOTICES.md behind the error.
notices:
		$(call require,go-licenses,go install github.com/google/go-licenses@latest)
		@{ go-licenses report ./... --ignore github.com/eclipse-keysealer/k8s-kms-plugin --template go-licenses.tpl > NOTICES.md.tmp && \
		   awk -f scripts/align-md-tables.awk NOTICES.md.tmp > NOTICES.md.aligned && \
		   mv NOTICES.md.aligned NOTICES.md; } || { rm -f NOTICES.md.tmp NOTICES.md.aligned; exit 1; }
		@rm -f NOTICES.md.tmp
		@echo "NOTICES.md generated"

## Lint
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_INSTALL_HINT := go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lint:
		$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) $(GOLANGCI_LINT) run

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
		$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) $(GOLANGCI_LINT) run --fix

## Vet
# Same check as the CI "Vet, build & test" job (.github/workflows/ci.yml).
vet:
		CGO_ENABLED=$(CGO_ENABLED) go vet ./...

## Vulnerability scan
# Runs govulncheck (reachability-aware, cross-checked against the Go vuln DB) —
# the same check as the CI govulncheck job (.github/workflows/security.yaml).
#
# Install govulncheck:
#   go install golang.org/x/vuln/cmd/govulncheck@latest
GOVULNCHECK ?= govulncheck

govulncheck:
		$(call require,$(GOVULNCHECK),go install golang.org/x/vuln/cmd/govulncheck@latest)
		CGO_ENABLED=$(CGO_ENABLED) $(GOVULNCHECK) -show verbose ./...

## Security scan
# Runs gosec (https://github.com/securego/gosec) — a static-analysis security
# scanner for Go code. Complements govulncheck (dependency CVEs) by flagging
# insecure code patterns in this module itself.
#
# Install gosec:
#   go install github.com/securego/gosec/v2/cmd/gosec@latest
GOSEC ?= gosec

gosec:
		$(call require,$(GOSEC),go install github.com/securego/gosec/v2/cmd/gosec@latest)
		CGO_ENABLED=$(CGO_ENABLED) $(GOSEC) ./...

## SAST
coverage:
		mkdir -p build
		CGO_ENABLED=$(CGO_ENABLED) go test -race -v -coverprofile build/coverage.out ./pkg/... ./cmd/...
		go tool cover -html=build/coverage.out -o build/coverage.html

## Build

# Local dev build (native arch)
build:
		@go version
		$(call require,$(LINUX_AMD64_GCC),$(CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME) cmd/k8s-kms-plugin/main.go

build-linux-amd64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/amd64"
		@go version
		$(call require,$(LINUX_AMD64_GCC),$(CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 CC=$(LINUX_AMD64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_amd64 cmd/k8s-kms-plugin/main.go

build-linux-amd64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/amd64 with debug option"
		@go version
		$(call require,$(LINUX_AMD64_GCC),$(CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 CC=$(LINUX_AMD64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_amd64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

build-linux-arm64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/arm64"
		@go version
		$(call require,$(LINUX_ARM64_GCC),$(ARM64_CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 CC=$(LINUX_ARM64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_arm64 cmd/k8s-kms-plugin/main.go

build-linux-arm64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/arm64 with debug option"
		@go version
		$(call require,$(LINUX_ARM64_GCC),$(ARM64_CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 CC=$(LINUX_ARM64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_arm64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

build-linux-riscv64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/riscv64"
		@go version
		$(call require,$(LINUX_RISCV64_GCC),$(RISCV64_CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=riscv64 CC=$(LINUX_RISCV64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_riscv64 cmd/k8s-kms-plugin/main.go

build-linux-riscv64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/riscv64 with debug option"
		@go version
		$(call require,$(LINUX_RISCV64_GCC),$(RISCV64_CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=riscv64 CC=$(LINUX_RISCV64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_riscv64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

## Docs
# The generated markdown is committed, so this target is deliberately reproducible: running it
# twice on the same tree produces byte-identical files, and a diff therefore means a real CLI
# change. Build and CI-run provenance is added to the front matter only when --provenance is set,
# which `k8s-kms-plugin docs` enables automatically when GITHUB_ACTIONS=true — the published
# documentation records the exact run that built it without dirtying the committed tree.
#
# DOC_FLAGS is passed through to the docs command. Use it to force the provenance setting, which
# otherwise follows GITHUB_ACTIONS: inside a workflow, checking whether the committed output is
# up to date requires `make doc DOC_FLAGS=--provenance=false`, or the comparison always differs by
# the commit hash and run URL it just stamped in.
DOC_FLAGS ?=

doc:
		@go run -ldflags="$(GIT_INFO_LDFLAGS)" cmd/k8s-kms-plugin/main.go docs --output-dir docs/cli-user-interface/markdown/ $(DOC_FLAGS)
		@go run -ldflags="$(GIT_INFO_LDFLAGS)" cmd/k8s-kms-plugin/main.go docs --output-dir docs/cli-user-interface/txt/ --format cli-table-pretty $(DOC_FLAGS)

# Regenerate docs/glossary.md from docs/termbase.yaml.
#
# The published site renders the glossary from the same YAML through Hextra's `glossary` layout,
# which ignores the page body — the generated Markdown table exists so the terms also show up on
# GitHub. Run this after editing termbase.yaml and commit both files; `glossary-check` is what CI
# runs to make sure that happened.
glossary:
		@python3 scripts/gen-glossary.py

glossary-check:
		@python3 scripts/gen-glossary.py --check

# Verify every relative Markdown link and #anchor across README.md, CHANGELOG.md and docs/.
# Anchors rot silently, so this is the check that catches a documentation restructure breaking
# cross-references. External http(s) links are not fetched.
check-doc-links:
		@python3 scripts/check-doc-links.py

## Documentation site (Hugo + Hextra)
# The site config lives in website/ and *mounts* ../docs as its content, so docs/ stays the single
# source of truth and keeps rendering on GitHub. The theme is a Hugo Module pinned in
# website/go.mod, kept out of the plugin's own go.mod on purpose.
#
# Hugo does not need to be the extended build: Hextra ships its Tailwind CSS precompiled.
HUGO ?= hugo
HUGO_INSTALL_HINT := go install github.com/gohugoio/hugo@latest
SITE_DIR := website

# The documentation's own version, shown in the navbar and the footer of every published page.
# Passed as build-time parameters rather than committed anywhere, so nothing can go stale: a page
# claiming the wrong version is worse than one that says it does not know. A build with none of these
# set renders "unversioned local build" instead of a blank or a lie — see
# website/layouts/_partials/custom/footer.html.
#
# HUGO_PARAMS_<NAME> is Hugo's env-var route into site params; the lookup is case-insensitive, so
# HUGO_PARAMS_DOCSVERSION reaches site.Params.docsVersion.
SITE_VERSION_ENV = \
	HUGO_PARAMS_DOCSVERSION="$(VERSION)" \
	HUGO_PARAMS_DOCSCOMMIT="$(COMMIT_LONG)" \
	HUGO_PARAMS_DOCSBUILDDATE="$(BUILD_DATE)"

site:
		$(call require,$(HUGO),$(HUGO_INSTALL_HINT))
		cd $(SITE_DIR) && $(SITE_VERSION_ENV) $(HUGO) --gc --minify
		@$(MAKE) --no-print-directory check-site
		@echo "Site built in $(SITE_DIR)/public"

# Verify the BUILT site: that every stylesheet, script, image and page link it references actually
# exists in the output, that no URL carries the baseURL path twice, and that in-page anchors resolve.
# `hugo` exiting 0 does not cover any of that — a site with no CSS and dead navigation still builds.
check-site:
		@python3 scripts/check-site-output.py $(SITE_DIR)/public

site-serve:
		$(call require,$(HUGO),$(HUGO_INSTALL_HINT))
		cd $(SITE_DIR) && $(SITE_VERSION_ENV) $(HUGO) server --buildDrafts

# Removes the build output and Hugo's module/resource caches.
site-clean:
		rm -rf $(SITE_DIR)/public $(SITE_DIR)/resources $(SITE_DIR)/.hugo_build.lock

## Testing
test:
		@CGO_ENABLED=$(CGO_ENABLED) go test -race ./pkg/... ./cmd/...

test-integration:
		@CGO_ENABLED=$(CGO_ENABLED) go test -race -v ./test/integration/...

test-e2e: build
		@CGO_ENABLED=$(CGO_ENABLED) go test -race -v ./test/e2e/...

# Go native fuzzing. `make test` already replays every target's seed corpus as an
# ordinary unit test; this target additionally runs the mutation engine, which only
# `go test -fuzz` does. `go test` fuzzes one target in one package per invocation, so
# loop over both. A failing input is written to <pkg>/testdata/fuzz/<target>/ — commit
# it, it then becomes a permanent regression seed replayed by `make test`.
FUZZ_PKGS ?= ./pkg/providers/ ./cmd/k8s-kms-plugin/cmd/
FUZZTIME ?= 60s
fuzz:
		@for pkg in $(FUZZ_PKGS); do \
			for target in $$(go test -list 'Fuzz.*' $$pkg | grep '^Fuzz'); do \
				echo "==> $$pkg $$target ($(FUZZTIME))"; \
				CGO_ENABLED=$(CGO_ENABLED) go test -run '^$$' -fuzz "^$$target$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
			done; \
		done

## Container image
# The Containerfile does not compile anything by default: `image` builds the
# binary with the LDFLAGS above, then packages dist/$(BINARY_NAME) into the
# runtime image. The released ghcr.io image is built by ko via goreleaser.
CONTAINER_ENGINE ?= podman
# Docker works too: run make with CONTAINER_ENGINE=docker
CONTAINER_ENGINE_INSTALL_HINT := sudo apt-get install podman
IMAGE_REGISTRY ?= ghcr.io
IMAGE_REPOSITORY ?= eclipse-keysealer/$(PROJECT_NAME)
IMAGE_TAG ?= $(VERSION)
IMAGE ?= $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY):$(IMAGE_TAG)

# Single source of truth for the image description: passed both as the
# Containerfile LABEL and as the manifest annotation below, so the two agree.
IMAGE_DESCRIPTION ?= gRPC service that leverages a remote or local HSM/TPM to encrypt Kubernetes data at-rest with KMS v2.

# --annotation writes manifest-level OCI annotations (what GitHub reads to fill
# in the ghcr.io package page). It is a podman/buildah flag: docker build has no
# equivalent -- buildx needs --output type=image,annotation.* -- so it is only
# passed when the engine actually supports it, keeping CONTAINER_ENGINE=docker working.
IMAGE_ANNOTATIONS = $(if $(filter podman buildah,$(notdir $(CONTAINER_ENGINE))),\
	--annotation "org.opencontainers.image.description=$(IMAGE_DESCRIPTION)")

# OCI labels that cannot be derived inside the build
IMAGE_BUILD_ARGS = \
	--build-arg LABEL_CREATED="$(BUILD_DATE)" \
	--build-arg LABEL_VERSION="$(VERSION)" \
	--build-arg LABEL_REVISION="$(COMMIT_LONG)" \
	--build-arg LABEL_REF_NAME="$(IMAGE_TAG)" \
	--build-arg LABEL_DESCRIPTION="$(IMAGE_DESCRIPTION)" \
	$(IMAGE_ANNOTATIONS)

image: build
		@echo "Makefile: Building container image $(IMAGE) from dist/$(BINARY_NAME)"
		$(call require,$(CONTAINER_ENGINE),$(CONTAINER_ENGINE_INSTALL_HINT))
		$(CONTAINER_ENGINE) build -f Containerfile \
			--build-arg BINARY=$(DIST_DIR)/$(BINARY_NAME) \
			$(IMAGE_BUILD_ARGS) \
			-t $(IMAGE) .

# Self-contained variant: compiles inside the builder stage instead of reusing
# dist/. Useful where `make build` cannot run (no Go toolchain, cross-arch).
image-from-source:
		@echo "Makefile: Building container image $(IMAGE) from source"
		$(call require,$(CONTAINER_ENGINE),$(CONTAINER_ENGINE_INSTALL_HINT))
		$(CONTAINER_ENGINE) build -f Containerfile \
			--build-arg BINARY_SOURCE=source \
			--build-arg VERSION="$(VERSION)" \
			--build-arg COMMIT_LONG="$(COMMIT_LONG)" \
			--build-arg COMMIT_SHORT="$(COMMIT_SHORT)" \
			--build-arg COMMIT_TIMESTAMP="$(COMMIT_TIMESTAMP)" \
			--build-arg BUILD_DATE="$(BUILD_DATE)" \
			--build-arg IS_GIT_DIRTY="$(IS_GIT_DIRTY)" \
			$(IMAGE_BUILD_ARGS) \
			-t $(IMAGE) .

## Release
GORELEASER ?= goreleaser
GORELEASER_INSTALL_HINT := go install github.com/goreleaser/goreleaser/v2@latest

release-local-test:
		@echo "Makefile: Running goreleaser release --clean for project $(PROJECT_NAME)"
		$(call require,$(GORELEASER),$(GORELEASER_INSTALL_HINT))
		LDFLAGS="$(GIT_INFO_LDFLAGS) -s -w" $(GORELEASER) release --clean --skip sign,validate,ko

release:
		@echo "Makefile: Running goreleaser release --clean for project $(PROJECT_NAME)"
		$(call require,$(GORELEASER),$(GORELEASER_INSTALL_HINT))
		LDFLAGS="$(GIT_INFO_LDFLAGS) -s -w" $(GORELEASER) release --clean

get-ldflags:
		@echo "$(GIT_INFO_LDFLAGS) -s -w"

# Fail if the current git tag contains characters that the VERSION sanitization
# above would strip. The build targets sanitize and warn; this target turns the
# same condition into a hard error, so CI can reject a malicious tag outright.
check-version:
		@raw="$$(git describe --tags --always --dirty 2>/dev/null)"; \
		safe="$$(printf '%s' "$$raw" | tr -cd 'A-Za-z0-9._+-')"; \
		if [ "$$safe" != "$$raw" ]; then \
			echo "error: git tag '$$raw' contains characters unsafe for build metadata" >&2; \
			exit 1; \
		fi

## Clean
clean:
		@echo "Makefile: cleaning dist directory"
		rm -rf $(DIST_DIR)
