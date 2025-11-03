.PHONY: all build test validate package package-helm clean

all: build

build:
	@echo "--- Building webhook binary ---"
	@bash -c 'source scripts/version && \
	mkdir -p bin && \
	docker build \
		--file package/Dockerfile \
		--target binary \
		--build-arg ARCH=$${ARCH} \
		--build-arg VERSION=$${VERSION} \
		--build-arg COMMIT=$${COMMIT} \
		-t rancher/webhook:binary-$${TAG} \
		. && \
	CONTAINER_ID=$$(docker create rancher/webhook:binary-$${TAG} echo) && \
	docker cp $$CONTAINER_ID:/webhook ./bin/webhook && \
	docker rm $$CONTAINER_ID'

test:
	./scripts/test

validate:
	./scripts/validate

package-helm:
	./scripts/package-helm

package: build package-helm
	./scripts/package

clean:
	rm -rf bin dist
