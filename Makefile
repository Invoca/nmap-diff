.PHONY: test build build-and-push-image

PKG=github.com/invoca/nmap-diff

test:
	go1.14 fmt ./pkg/... ./cmd/...
	go1.14 vet ./pkg/... ./cmd/...
	go1.14 test ./pkg/... ./cmd/... --race $(PKG) -v

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
	#echo $(GCLOUD_KEY) | base64 --decode > gcloud.p12
	gcloud auth activate-service-account $(GCLOUD_EMAIL)
	#ssh-keygen -f ~/.ssh/google_compute_engine -N ""
	echo "Pushing images to GCR"
	gcloud docker push gcr.io/$(CLOUDSDK_CORE_PROJECT)/nmap-diff:server-$(TAG)
