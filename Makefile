BINARY_NAME = any-oidc-proxy
DOCKER_IMAGE = docker.io/maintainer64/any-oidc-proxy
VERSION = $(shell git describe --tags --always --dirty)

.PHONY: build docker-build docker-push release

build:
	@echo "Building $(BINARY_NAME)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o dist/$(BINARY_NAME) ./cmd

docker-build: build
	@echo "Building Docker image..."
	docker build --platform linux/amd64 -t $(DOCKER_IMAGE):$(VERSION) -t $(DOCKER_IMAGE):latest .

docker-push: docker-build
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest

release: docker-push
	@echo "Release $(VERSION) completed!"

test:
	go test ./... -v

clean:
	rm -rf dist/
