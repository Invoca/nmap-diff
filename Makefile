.PHONY: test build build-and-push-image

SHELL := /bin/bash

PKG=github.com/invoca/nmap-diff

test:
	go fmt ./pkg/... ./cmd/...
	go vet ./pkg/... ./cmd/...
	go test ./pkg/... ./cmd/... --race $(PKG) -v

build-and-push-image:
	gcloud auth activate-service-account --key-file=/tmp/key_file.json
	docker login -u "$(DOCKER_USERNAME)" -p "$(DOCKER_PASSWORD)" quay.io
	docker build -f resources/Dockerfile.server -t quay.io/invoca/nmap-diff:server-$(BRANCH_NAME) .
	docker build -f resources/Dockerfile.server -t gcr.io/$(CLOUDSDK_CORE_PROJECT)/nmap-diff:server-$(BRANCH_NAME) .
	docker build -f resources/Dockerfile.cmd -t quay.io/invoca/nmap-diff:cmd-$(BRANCH_NAME) .
	echo "Pushing images to quay with tag $(BRANCH_NAME)"
	docker push quay.io/invoca/nmap-diff:server-$(BRANCH_NAME)
	docker push quay.io/invoca/nmap-diff:cmd-$(BRANCH_NAME)
	echo "Setting up gcloud cli"
	gcloud auth configure-docker
	docker push gcr.io/$(CLOUDSDK_CORE_PROJECT)/nmap-diff:server-$(BRANCH_NAME)
