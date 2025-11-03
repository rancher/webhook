# ===============
# Build Stage
# ===============
FROM registry.suse.com/bci/golang:1.24 AS build

ARG ARCH
ARG VERSION
ARG COMMIT

WORKDIR /src

# Copy all source and vendor dependencies
COPY . .

# Build the webhook binary
RUN CGO_ENABLED=0 GOARCH=${ARCH} go build -ldflags="-X main.Version=${VERSION} -X main.GitCommit=${COMMIT} -extldflags -static -s" -o /dist/webhook .

# ===============
# Binary Stage (for extracting the binary)
# ===============
FROM scratch AS binary
COPY --from=build /dist/webhook /

# ===============
# Final Stage
# ===============
FROM registry.suse.com/bci/bci-micro:15.7

ARG user=webhook

RUN echo "$user:x:1000:1000::/home/$user:/bin/bash" >> /etc/passwd && \
    echo "$user:x:1000:" >> /etc/group && \
    mkdir /home/$user && \
    chown -R $user:$user /home/$user

# Copy the compiled binary from the build stage
COPY --from=build /dist/webhook /usr/bin/

USER $user

CMD ["webhook"]
