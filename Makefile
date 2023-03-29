.PHONY: docker docker-itest docker-test docker-test-all docker-check docker-shell itest test test-all

IMG_NAME      := lndsigner-builder

CPLATFORM   := $(shell uname -m)

ifeq ($(CPLATFORM), x86_64)
	GOPLATFORM := amd64
endif

ifeq ($(CPLATFORM), aarch64)
	GOPLATFORM := arm64
endif

ifeq ($(CPLATFORM), arm64)
	GOPLATFORM := arm64
	CPLATFORM := aarch64
endif 

GOVER         := 1.19.7
LND           := v0.16.0-beta
BITCOIND      := 24.0.1
VAULT         := 1.12.2

# docker builds a builder image for the host platform if one isn't cached.
docker:
	docker build -t $(IMG_NAME):latest --build-arg cplatform=$(CPLATFORM) \
		--build-arg goplatform=$(GOPLATFORM) --build-arg gover=$(GOVER) \
		--build-arg lnd=$(LND) --build-arg bitcoind=$(BITCOIND) \
		--build-arg vault=$(VAULT) -f Dockerfile.dev .

# docker-itest runs itests in a docker container, then removes the container.
docker-itest: docker
	docker run -t --rm \
		--mount type=bind,source=$(CURDIR),target=/app $(IMG_NAME):latest \
		make itest

# docker-test runs unit tests in a docker container, then removes the container.
docker-test: docker
	docker run -t --rm \
		--mount type=bind,source=$(CURDIR),target=/app $(IMG_NAME):latest \
		make test

# docker-test-all runs unit and integration tests in a docker container, then
# removes the container.
docker-test-all: docker
	docker run -t --rm \
		--mount type=bind,source=$(CURDIR),target=/app $(IMG_NAME):latest \
		make test-all

# docker-shell opens a shell to a dockerized environment with all dependencies
# and also dlv installed for easy debugging, then removes the container.
docker-shell: docker
	docker run -it --rm \
		--mount type=bind,source=$(CURDIR),target=/app $(IMG_NAME):latest \
		bash -l 

itest:
	go install -race -buildvcs=false ./cmd/... && go test -v -count=1 -race -tags=itest -cover ./itest

test:
	go test -v -count=1 -race -cover ./...

test-all:
	go install -race -buildvcs=false ./cmd/... && go test -v -count=1 -race -tags=itest -cover ./...
