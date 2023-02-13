ARG gover=1.19.5

# Build a release binary

FROM golang:$gover AS release-builder

COPY . /go/src/github.com/bottlepay/lndsigner

RUN cd /go/src/github.com/bottlepay/lndsigner \
    && CGO_ENABLED=0 go install -buildvcs=false \
       github.com/bottlepay/lndsigner/cmd/...

### Build an Alpine image
FROM alpine:3.16 as alpine

# Update CA certs
RUN apk add --no-cache ca-certificates && rm -rf /var/cache/apk/*

# Copy over app binary
COPY --from=release-builder /go/bin/lndsignerd /usr/bin/lndsignerd

# Add a user
RUN mkdir -p /app && adduser -D lndsignerd && chown -R lndsignerd /app
USER lndsignerd

WORKDIR /app/

CMD [ "/usr/bin/lndsignerd" ]

### Build a Debian image
FROM debian:bullseye-slim as debian

# Update CA certs
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy over app binary
COPY --from=release-builder /go/bin/lndsignerd /usr/bin/lndsignerd

# Add a user
RUN mkdir -p /app && adduser --disabled-login lndsignerd && chown -R lndsignerd /app
USER lndsignerd

WORKDIR /app

CMD [ "/usr/bin/lndsignerd" ]
