# syntax=docker/dockerfile:1.7

# Builds the bridge into a distroless image, which holds nothing but the binary and CA certificates

ARG GO_VERSION=1.27
ARG VERSION=dev

FROM golang:${GO_VERSION}-alpine AS build
ARG VERSION
WORKDIR /src
COPY --link go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY --link cmd ./cmd
COPY --link internal ./internal
COPY --link resource ./resource
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/bridge \
      ./cmd/bridge

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/bridge /bridge
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/bridge"]
CMD ["--config", "/etc/bridge/config.yaml"]
