# ===============
# Build Stage
# ===============
FROM --platform=$BUILDPLATFORM registry.suse.com/bci/golang:1.24@sha256:ae722bb8954485d10eb26d90c14d521d90810d8b0c84c3c72b58cbb1fc1ee284 AS build

# Set up build cache
ENV GOMODCACHE=/root/.cache/go/modcache
ENV GOCACHE=/root/.cache/go/cache
ENV CGO_ENABLED=0

WORKDIR /src

# Define build arguments
ARG VERSION
ARG COMMIT
ARG LINKFLAGS="-extldflags -static -s"
ARG LDFLAGS="-X main.Version=${VERSION} -X main.GitCommit=${COMMIT} ${LINKFLAGS}"

# Download dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache,id=rancher go mod download

# ===============
# Webhook Binary Build Stage
# ===============
FROM --platform=$BUILDPLATFORM build AS webhook-build
ARG TARGETOS
ARG TARGETARCH
# Copy source and build the webhook binary
COPY pkg/ pkg/
COPY main.go ./
RUN --mount=type=cache,target=/root/.cache,id=rancher GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /dist/webhook .

# ===============
# Binary Stage (for extracting the main binary)
# ===============
FROM scratch AS binary
COPY --from=webhook-build /dist/webhook /webhook

# ===============
# Test Stage
# ===============
FROM build AS test
COPY . .
RUN --mount=type=cache,target=/root/.cache,id=rancher go test --coverpkg=./pkg/... -coverprofile=coverage.out --count=1 ./pkg/...
RUN cat coverage.out | awk 'BEGIN {cov=0; stat=0;} $3!="" { cov+=($3==1?$2:0); stat+=$2; } END {printf("Total coverage: %.2f%% of statements\n", (cov/stat)*100);}'

# ===============
# Validate Stage
# ===============
FROM build AS validate
# renovate: datasource=github-releases depName=golangci/golangci-lint
ARG GOLANGCI_LINT_VERSION=1.64.6
# renovate: datasource=github-release-attachments depName=golangci/golangci-lint digestVersion=v1.64.6
ARG GOLANGCI_LINT_SUM_amd64=71e290acbacb7b3ba4f68f0540fb74dc180c4336ac8a6f3bdcd7fcc48b15148d
# renovate: datasource=github-release-attachments depName=golangci/golangci-lint digestVersion=v1.64.6
ARG GOLANGCI_LINT_SUM_arm64=99a7ff13dec7a8781a68408b6ecb8a1c5e82786cba3189eaa91d5cdcc24362ce
RUN set -e; \
    ARCH=$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/'); \
    TARBALL="golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${ARCH}.tar.gz"; \
    URL="https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/${TARBALL}"; \
    case "${ARCH}" in \
      amd64) SUM="${GOLANGCI_LINT_SUM_amd64}" ;; \
      arm64) SUM="${GOLANGCI_LINT_SUM_arm64}" ;; \
      *) echo "Unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o "/tmp/${TARBALL}" "${URL}"; \
    echo "${SUM}  /tmp/${TARBALL}" | sha256sum --check; \
    tar -xzf "/tmp/${TARBALL}" -C /tmp "golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${ARCH}/golangci-lint"; \
    mv "/tmp/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${ARCH}/golangci-lint" /usr/local/bin/golangci-lint; \
    rm -rf "/tmp/${TARBALL}" "/tmp/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${ARCH}"
COPY . .
RUN --mount=type=cache,target=/root/.cache,id=rancher golangci-lint run
RUN ./scripts/validate-kube-version
RUN ./scripts/validate-rancher-version

# ===============
# Integration Test Build Stage
# ===============
FROM build AS integration-test-build
COPY . .
RUN --mount=type=cache,target=/root/.cache,id=rancher go test ./tests/integration/... -c -o /dist/rancher-webhook-integration.test

# ===============
# Test Binary Stage to extract the integration test binary
# ===============
FROM scratch AS integration-test-binary
COPY --from=integration-test-build /dist/rancher-webhook-integration.test /rancher-webhook-integration.test

# ===============
# Final Stage
# ===============
FROM registry.suse.com/bci/bci-micro:15.7@sha256:5ca1a44ca5be8afd3e4abc721abf1efe6b0fe69b83cf01a0c204c16160913edc

ARG user=webhook

RUN echo "$user:x:1000:1000::/home/$user:/bin/bash" >> /etc/passwd && \
    echo "$user:x:1000:" >> /etc/group && \
    mkdir /home/$user && \
    chown -R $user:$user /home/$user

# Copy the compiled binary from the webhook-build stage
COPY --from=webhook-build /dist/webhook /usr/bin/

USER $user

CMD ["webhook"]
