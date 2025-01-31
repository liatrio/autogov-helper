FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .

RUN go mod download

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-X main.version=${VERSION:-dev}" -o gh-attest-util .

FROM alpine:3.21
LABEL org.opencontainers.image.title="gh-attest-util" \
      org.opencontainers.image.description="GitHub Attestation Utility" \
      org.opencontainers.image.vendor="YourOrg" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/laitrio/gh-attest-util"

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/gh-attest-util /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/gh-attest-util"]
