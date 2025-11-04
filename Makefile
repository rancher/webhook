.PHONY: all build test-binary test validate package package-helm clean

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
		--platform=linux/$${ARCH} \
		--output=type=local,dest=./bin \
		. '

test-binary:
	@echo "--- Building Integration Test Binary ---"
	@bash -c 'source scripts/version && \
	mkdir -p bin && \
	docker buildx build \
		--file package/Dockerfile \
		--target test-binary \
		--platform=linux/$${ARCH} \
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

package: test validate build package-helm
	@echo "--- Packaging Final Image ---"
	@bash -c 'source scripts/version && \
	docker buildx build \
		--file package/Dockerfile \
		--build-arg VERSION=$${VERSION} \
		--build-arg COMMIT=$${COMMIT} \
		--platform=linux/$${ARCH} \
		-t rancher/webhook:$${TAG} \
		--load \
		. && \
	mkdir -p dist && \
	chmod a+rwx dist && \
	docker save -o dist/rancher-webhook-image.tar rancher/webhook:$${TAG} && \
	echo IMAGE_TAG=$${TAG} > dist/image_tag'

clean:
	rm -rf bin dist
