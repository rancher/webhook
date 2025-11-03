.PHONY: all build test validate package package-helm clean

all: package

build:
	@echo "--- Building Webhook Image & Binary ---"
	@bash -c 'source scripts/version && \
	docker build \
		--file package/Dockerfile \
		--build-arg ARCH=$${ARCH} \
		--build-arg VERSION=$${VERSION} \
		--build-arg COMMIT=$${COMMIT} \
		-t rancher/webhook:$${TAG} \
		. && \
	mkdir -p bin && \
	CONTAINER_ID=$$(docker create rancher/webhook:$${TAG} echo) && \
	docker cp $$CONTAINER_ID:/usr/bin/webhook ./bin/webhook && \
	docker rm $$CONTAINER_ID'

test:
	./scripts/test

validate:
	./scripts/validate

package-helm:
	./scripts/package-helm

package: build package-helm
	@echo "--- Packaging Release Artifacts ---"
	@bash -c 'source scripts/version && \
	mkdir -p dist && \
	chmod a+rwx dist && \
	docker save -o dist/rancher-webhook-image.tar rancher/webhook:$${TAG} && \
	echo IMAGE_TAG=$${TAG} > dist/image_tag'

clean:
	rm -rf bin dist
