.PHONY: test build build-and-push-image

PKG=github.com/invoca/nmap-diff

test:
	go fmt ./pkg/... ./cmd/...
	go vet ./pkg/... ./cmd/...
	go test ./pkg/... ./cmd/... --race $(PKG) -v

build-and-push-image:
	@echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin quay.io
	docker build -f resources/Dockerfile.server -t quay.io/invoca/nmap-diff:sever-$(TAG) .
	docker build -f resources/Dockerfile.cmd -t quay.io/invoca/nmap-diff:cmd-$(TAG) .
	echo "Pushing images with tag $(TAG)"
	docker push quay.io/invoca/nmap-diff:sever-$(TAG)
	docker push quay.io/invoca/nmap-diff:cmd-$(TAG)
