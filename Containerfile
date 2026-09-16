# syntax=docker/dockerfile:1

# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

#==============================================================================#
# k8s-kms-plugin production container image.
#
# The binary is NOT compiled here by default. The Makefile and the GitHub
# workflows are the single source of truth for how k8s-kms-plugin is built
# (LDFLAGS, cross-compilers, trimpath), so this file only packages the artifact
# they produce:
#
#   make build                       # -> dist/k8s-kms-plugin
#   podman build -f Containerfile -t k8s-kms-plugin:dev .
#
# or in one step:
#
#   make image
#
# Package a specific goreleaser artifact instead:
#
#   podman build -f Containerfile \
#     --build-arg BINARY=dist/k8s-kms-plugin_linux_amd64_v1.0.0 \
#     -t k8s-kms-plugin:v1.0.0 .
#
# The from-source build is still available as an opt-in for a self-contained,
# `make`-less build (CI sandboxes, `docker buildx` multi-arch):
#
#   podman build -f Containerfile --build-arg BINARY_SOURCE=source .
#   docker buildx build --platform linux/amd64,linux/arm64,linux/riscv64 \
#       --build-arg BINARY_SOURCE=source -f Containerfile .
#
# Build context exclusions live in .containerignore; .dockerignore is a symlink
# to it, so podman and docker/buildx apply the same rules from one file.
#
# Debian (glibc) is used rather than Alpine (musl) because the plugin is built
# with CGO_ENABLED=1 and dlopen()s vendor PKCS#11 libraries at runtime, which
# are themselves linked against glibc.
#
# NOTE: the released image published to ghcr.io is built by `ko` via
# .goreleaser.yml, not by this file. This Containerfile is the local/CI build
# and the target of the Trivy image scan.
#
# NOTE: vendor PKCS#11 client libraries (Thales Luna "Chrystoki", DPoD, ...) are
# proprietary and deliberately NOT baked into this image. Bind-mount them at
# runtime instead - see the "Running" section at the bottom of this file.
#==============================================================================#

#------------------------------------------------------------------------------
# Where the binary comes from: "prebuilt" (make / goreleaser output) or "source"
#------------------------------------------------------------------------------
ARG BINARY_SOURCE=prebuilt

# Path of the prebuilt binary inside the build context. Matches `make build`.
ARG BINARY=dist/k8s-kms-plugin

#------------------------------------------------------------------------------
# Versions. Keep GOLANG_VERSION in sync with go.mod and .go-version.
# Only used by the opt-in "source" build.
#------------------------------------------------------------------------------
ARG GOLANG_VERSION=1.27.1

# Debian 13 "Trixie"
ARG DEBIAN_VERSION=trixie

# Builder image
ARG BUILDER_IMAGE_REGISTRY=docker.io/library
ARG BUILDER_IMAGE_NAME=golang
ARG BUILDER_IMAGE_TAG=${GOLANG_VERSION}-${DEBIAN_VERSION}

# Runtime image
ARG RUNTIME_IMAGE_REGISTRY=docker.io/library
ARG RUNTIME_IMAGE_NAME=debian
ARG RUNTIME_IMAGE_TAG=${DEBIAN_VERSION}-slim

# For the OCI base image annotations of the final stage
ARG BASE_REGISTRY=${RUNTIME_IMAGE_REGISTRY}
ARG BASE_IMAGE=${RUNTIME_IMAGE_NAME}
ARG BASE_IMAGE_TAG=${RUNTIME_IMAGE_TAG}

# Non-root runtime user
ARG APP_USER="k8s-kms-plugin"
ARG APP_USER_UID="1234"
ARG APP_GROUP="k8s-kms-plugin"
ARG APP_GROUP_GID="1234"

# Where the plugin binary lands and where it is expected to open its gRPC socket
ARG APP_BIN_DIR="/usr/bin"
ARG APP_RUN_DIR="/run/k8s-kms-plugin"

#==============================================================================#
# binary-prebuilt - default. Takes the artifact produced by `make build`,
# `make build-linux-<arch>` or goreleaser. No toolchain, no network, no
# duplicated build flags: the version metadata is already linked into it.
#==============================================================================#
FROM scratch AS binary-prebuilt

ARG BINARY

COPY ${BINARY} /out/k8s-kms-plugin

#==============================================================================#
# binary-source - opt-in (BINARY_SOURCE=source). Pinned to the *build* platform
# so the Go toolchain runs natively and cross-compiles for ${TARGETARCH}, which
# is much faster than QEMU emulation. Mirrors the Makefile build targets.
#==============================================================================#
FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE_REGISTRY}/${BUILDER_IMAGE_NAME}:${BUILDER_IMAGE_TAG} AS binary-source

# Provided automatically by BuildKit / buildah
ARG TARGETARCH
ARG TARGETOS

# CGO_ENABLED=1 is mandatory: the PKCS#11 binding (miekg/pkcs11) is cgo.
# Install only the cross toolchain matching the requested target architecture.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64)   packages="gcc libc6-dev" ;; \
      arm64)   packages="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      riscv64) packages="gcc-riscv64-linux-gnu libc6-dev-riscv64-cross" ;; \
      *)       echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends ${packages}; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first so the module cache layer is reused across source edits.
# vendor/ is gitignored, so the build resolves modules from the proxy.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY . .

#------------------------------------------------------------------------------
# Build metadata - consumed by pkg/version, mirrors the LDFLAGS in the Makefile.
# Left empty by default so a bare build still succeeds; the resulting binary
# then reports "unknown" for these fields. Prefer `make image`, which builds the
# binary with the Makefile LDFLAGS already applied.
#------------------------------------------------------------------------------
ARG VERSION=""
ARG COMMIT_LONG=""
ARG COMMIT_SHORT=""
ARG COMMIT_TIMESTAMP=""
ARG BUILD_DATE=""
ARG IS_GIT_DIRTY="false"

ARG GO_MODULE_NAME="github.com/eclipse-keysealer/k8s-kms-plugin"

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    set -eux; \
    case "${TARGETARCH}" in \
      amd64)   CC=gcc ;; \
      arm64)   CC=aarch64-linux-gnu-gcc ;; \
      riscv64) CC=riscv64-linux-gnu-gcc ;; \
    esac; \
    export CC CGO_ENABLED=1 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}"; \
    go build -trimpath \
      -ldflags="-s -w \
        -X '${GO_MODULE_NAME}/pkg/version.RawGitDescribe=${VERSION}' \
        -X '${GO_MODULE_NAME}/pkg/version.GitCommitIDLong=${COMMIT_LONG}' \
        -X '${GO_MODULE_NAME}/pkg/version.GitCommitIDShort=${COMMIT_SHORT}' \
        -X '${GO_MODULE_NAME}/pkg/version.GitCommitTimestamp=${COMMIT_TIMESTAMP}' \
        -X '${GO_MODULE_NAME}/pkg/version.GoVersion=$(go version)' \
        -X '${GO_MODULE_NAME}/pkg/version.BuildPlatform=${TARGETOS}/${TARGETARCH}' \
        -X '${GO_MODULE_NAME}/pkg/version.BuildDate=${BUILD_DATE}' \
        -X '${GO_MODULE_NAME}/pkg/version.GitDirtyStr=${IS_GIT_DIRTY}'" \
      -o /out/k8s-kms-plugin ./cmd/k8s-kms-plugin

#==============================================================================#
# binary - resolves to one of the two stages above. Stages that are not selected
# are never built.
#==============================================================================#
FROM binary-${BINARY_SOURCE} AS binary

#==============================================================================#
# Runtime - resolved for ${TARGETPLATFORM}, contains the plugin and nothing else
#==============================================================================#
FROM ${RUNTIME_IMAGE_REGISTRY}/${RUNTIME_IMAGE_NAME}:${RUNTIME_IMAGE_TAG} AS runtime

ARG APP_USER
ARG APP_USER_UID
ARG APP_GROUP
ARG APP_GROUP_GID
ARG APP_BIN_DIR
ARG APP_RUN_DIR

# ca-certificates is required to validate TLS when talking to a network HSM
# (Thales DPoD, Luna over NTLS). libltdl7 is dlopen()ed by several vendor
# PKCS#11 clients.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libltdl7; \
    rm -rf /var/lib/apt/lists/*

# Run without root privileges: the plugin only needs to read the PKCS#11 library
# and to create its gRPC socket.
RUN set -eux; \
    groupadd --gid ${APP_GROUP_GID} ${APP_GROUP}; \
    useradd --uid ${APP_USER_UID} --gid ${APP_GROUP_GID} \
            --home-dir /home/${APP_USER} --create-home \
            --shell /usr/sbin/nologin \
            --comment "k8s-kms-plugin service account" \
            ${APP_USER}; \
    install -d -o ${APP_USER} -g ${APP_GROUP} -m 0750 ${APP_RUN_DIR}

COPY --from=binary --chown=root:root --chmod=0755 \
     /out/k8s-kms-plugin ${APP_BIN_DIR}/k8s-kms-plugin

USER ${APP_USER_UID}:${APP_GROUP_GID}
WORKDIR /home/${APP_USER}

# gRPC is served over a Unix socket, so no port is exposed by default.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/bin/k8s-kms-plugin"]
CMD ["serve"]

#==============================================================================#
# Running
#==============================================================================#
# The image ships no PKCS#11 library. Point --p11-lib at one you bind-mount:
#
#   # SoftHSM (development only)
#   podman run --rm \
#     -v softhsm-tokens:/var/lib/softhsm/tokens \
#     -v /usr/lib/softhsm/libsofthsm2.so:/opt/p11/libsofthsm2.so:ro \
#     -v /run/k8s-kms-plugin:/run/k8s-kms-plugin \
#     k8s-kms-plugin:dev serve \
#       --provider softhsm \
#       --p11-lib /opt/p11/libsofthsm2.so \
#       --p11-label default --p11-pin changeme \
#       --p11-key-label kms-kek \
#       --socket /run/k8s-kms-plugin/k8s-kms-plugin.sock
#
#   # Thales Luna / DPoD - mount the vendor client read-only and export
#   # ChrystokiConfigurationPath so libCryptoki2.so finds Chrystoki.conf
#   podman run --rm \
#     -v /opt/luna:/opt/luna:ro \
#     -e ChrystokiConfigurationPath=/opt/luna/config \
#     -v /run/k8s-kms-plugin:/run/k8s-kms-plugin \
#     k8s-kms-plugin:dev serve \
#       --provider luna \
#       --p11-lib /opt/luna/lib/libCryptoki2.so \
#       --p11-label mypartition \
#       --p11-key-label kms-kek \
#       --socket /run/k8s-kms-plugin/k8s-kms-plugin.sock
#
# All flags also accept K8S_KMS_PLUGIN_* environment variables or a config file
# (--config); see `k8s-kms-plugin serve --help` and configs/config.example.yaml.

#==============================================================================#
# OCI annotations
# See https://github.com/opencontainers/image-spec/blob/main/annotations.md
#==============================================================================#
ARG LABEL_CREATED=""
ARG LABEL_AUTHOR="Thales Open Source <oss@thalesgroup.com>"
ARG LABEL_URL="ghcr.io/eclipse-keysealer/k8s-kms-plugin"
ARG LABEL_DOCUMENTATION="https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/README.md"
ARG LABEL_SOURCE="https://github.com/eclipse-keysealer/k8s-kms-plugin"
ARG LABEL_VERSION=""
ARG LABEL_REVISION=""
ARG LABEL_VENDOR="Thales"
ARG LABEL_LICENSES="MIT"
ARG LABEL_TITLE="k8s-kms-plugin"
ARG LABEL_REF_NAME=""
ARG LABEL_DESCRIPTION="gRPC service that leverages a remote or local HSM/TPM to encrypt Kubernetes data at-rest with KMS v2."
ARG LABEL_BASE_DIGEST=""
ARG BASE_REGISTRY
ARG BASE_IMAGE
ARG BASE_IMAGE_TAG
ARG LABEL_BASE_NAME="${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_IMAGE_TAG}"
LABEL org.opencontainers.image.created="${LABEL_CREATED}"
LABEL org.opencontainers.image.authors="${LABEL_AUTHOR}"
LABEL org.opencontainers.image.url="${LABEL_URL}"
LABEL org.opencontainers.image.documentation="${LABEL_DOCUMENTATION}"
LABEL org.opencontainers.image.source="${LABEL_SOURCE}"
LABEL org.opencontainers.image.version="${LABEL_VERSION}"
LABEL org.opencontainers.image.revision="${LABEL_REVISION}"
LABEL org.opencontainers.image.vendor="${LABEL_VENDOR}"
LABEL org.opencontainers.image.licenses="${LABEL_LICENSES}"
LABEL org.opencontainers.image.title="${LABEL_TITLE}"
LABEL org.opencontainers.image.ref.name="${LABEL_REF_NAME}"
LABEL org.opencontainers.image.description="${LABEL_DESCRIPTION}"
LABEL org.opencontainers.image.base.digest="${LABEL_BASE_DIGEST}"
LABEL org.opencontainers.image.base.name="${LABEL_BASE_NAME}"
