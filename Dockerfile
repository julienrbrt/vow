### Compile stage
FROM golang:1.26.1-bookworm AS build-env

ADD . /dockerbuild
WORKDIR /dockerbuild

RUN GIT_VERSION=$(git describe --tags --long --always || echo "dev-local") && \
    go mod tidy && \
    go build -ldflags "-X main.Version=$GIT_VERSION" -o vow ./cmd/vow

### Run stage
FROM debian:bookworm-slim AS run

RUN apt-get update && apt-get install -y dumb-init runit ca-certificates curl && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["dumb-init", "--"]

WORKDIR /
RUN mkdir -p data/vow
COPY --from=build-env /dockerbuild/vow /

CMD ["/vow", "run"]

LABEL org.opencontainers.image.source=https://pkg.rbrt.fr/vow
LABEL org.opencontainers.image.description="Vow ATProto PDS"
LABEL org.opencontainers.image.licenses=MIT
