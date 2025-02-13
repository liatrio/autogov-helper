FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .

RUN go mod download

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-X main.version=${VERSION:-dev}" -o autogov-helper .

FROM alpine:3.19
LABEL org.opencontainers.image.title="autogov-helper" \
      org.opencontainers.image.description="GitHub Attestation Utility" \
      org.opencontainers.image.vendor="Liatrio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/liatrio/autogov-helper"

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/autogov-helper /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/autogov-helper"]
