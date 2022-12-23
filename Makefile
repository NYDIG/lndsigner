.PHONY: docker docker-itest docker-test docker-test-all docker-check docker-shell itest test test-all

IMG_NAME      := lndsigner-builder

GOVER         := 1.19.5
GOPLATFORM    := amd64
CPPPLATFORM   := x86_64
LND           := v0.15.5-beta
BITCOIND      := 24.0.1
VAULT         := 1.12.2

# docker just tags the latest image to the builderstamp, in case the
# dependencies have been changed and a new image was built.
docker:
	docker build -t $(IMG_NAME):latest .

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
