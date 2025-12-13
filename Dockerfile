# syntax=docker/dockerfile:1

FROM golang:1.25 AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build linux binary for container runtime
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o /out/polis-core ./cmd/polis-core

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H -u 10001 polis

WORKDIR /app
COPY --from=builder /out/polis-core /app/polis-core

USER polis
EXPOSE 8090

ENTRYPOINT ["/app/polis-core"]
CMD ["--config", "/app/config.yaml", "--listen", ":8090", "--log-level", "info"]
