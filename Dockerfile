FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o gh-attest-util

FROM alpine:latest
COPY --from=builder /app/gh-attest-util /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/gh-attest-util"]