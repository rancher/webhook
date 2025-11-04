# Set default ARCH, but allow it to be overridden
UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_ARCH),x86_64)
    ARCH ?= amd64
else ifeq ($(UNAME_ARCH),aarch64)
    ARCH ?= arm64
else
    ARCH ?= $(UNAME_ARCH)
endif

# Export ARCH so it's available to subshells (like the scripts)
export ARCH
PLATFORM ?= linux/$(ARCH)

.PHONY: all build test-binary test validate package package-helm image clean

all: package

build:
	@echo "--- Building Webhook Binary ---"
	@bash -c 'source scripts/version && \
	mkdir -p bin && \
	docker buildx build \
		--file package/Dockerfile \
		--target binary \
		--build-arg VERSION=$${VERSION} \
		--build-arg COMMIT=$${COMMIT} \
		--platform=$(PLATFORM) \
		--output=type=local,dest=./bin \
		. '

test-binary:
	@echo "--- Building Integration Test Binary ---"
	@bash -c 'source scripts/version && \
	mkdir -p bin && \
	docker buildx build \
		--file package/Dockerfile \
		--target test-binary \
		--platform=$(PLATFORM) \
		--output=type=local,dest=./bin \
		. '

test:
	@echo "--- Running Unit Tests ---"
	@docker buildx build \
		--file package/Dockerfile \
		--target test \
		--progress=plain \
		.

validate:
	@echo "--- Validating ---"
	@docker buildx build \
        --file package/Dockerfile \
        --target validate \
        --progress=plain \
        .

package-helm:
	./scripts/package-helm

image: build
	@echo "--- Building Development Image ---"
	@bash -c 'source scripts/version && \
	docker buildx build \
		--file package/Dockerfile \
		--build-arg VERSION=$${VERSION} \
		--build-arg COMMIT=$${COMMIT} \
		--platform=$(PLATFORM) \
		-t rancher/webhook:$${TAG} \
		--load \
		. && \
	mkdir -p dist && \
	chmod a+rwx dist && \
	docker save -o dist/rancher-webhook-image.tar rancher/webhook:$${TAG} && \
	echo IMAGE_TAG=$${TAG} > dist/image_tag'

# package target is for CI, ensuring tests and validation run first
package: test validate image package-helm

clean:
	rm -rf bin dist
