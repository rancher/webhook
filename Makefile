.PHONY: all build test validate package package-helm clean

all: build

build:
	./scripts/build

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
