# ===============
# Build Stage
# ===============
FROM --platform=$BUILDPLATFORM registry.suse.com/bci/golang:1.25 AS build

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
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin v2.7.1
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
FROM registry.suse.com/bci/bci-micro:15.7

ARG user=webhook

RUN echo "$user:x:1000:1000::/home/$user:/bin/bash" >> /etc/passwd && \
    echo "$user:x:1000:" >> /etc/group && \
    mkdir /home/$user && \
    chown -R $user:$user /home/$user

# Copy the compiled binary from the webhook-build stage
COPY --from=webhook-build /dist/webhook /usr/bin/

USER $user

CMD ["webhook"]
