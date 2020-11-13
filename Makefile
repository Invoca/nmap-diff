.PHONY: test build build-and-push-image

PKG=github.com/invoca/nmap-diff

test:
	go fmt ./pkg/... ./cmd/...
	go vet ./pkg/... ./cmd/...
	go test ./pkg/... ./cmd/... --race $(PKG) -v

build-and-push-image:
	@echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin quay.io
	docker build -f resources/Dockerfile.server -t quay.io/invoca/nmap-diff:server-$(TAG) .
	docker build -f resources/Dockerfile.server -t gcr.io/$(CLOUDSDK_CORE_PROJECT)/nmap-diff:server-$(TAG) .
	docker build -f resources/Dockerfile.cmd -t quay.io/invoca/nmap-diff:cmd-$(TAG) .
	echo "Pushing images to quay with tag $(TAG)"
	docker push quay.io/invoca/nmap-diff:sever-$(TAG)
	docker push quay.io/invoca/nmap-diff:cmd-$(TAG)
	echo "Setting up gcloud cli"
	curl https://sdk.cloud.google.com | bash
	source /home/travis/google-cloud-sdk/path.bash.inc
	echo "$(GOOGLE_SERVICE_ACCOUNT_DATA)" | base64 -d > $(GOOGLE_APPLICATION_CREDENTIALS)
	gcloud version
	gcloud auth activate-service-account
	gcloud auth configure-docker $(CLOUDSDK_CORE_PROJECT)
	echo "Pushing images to GCR"
	docker push gcr.io/$(CLOUDSDK_CORE_PROJECT)/nmap-diff:server-$(TAG)
