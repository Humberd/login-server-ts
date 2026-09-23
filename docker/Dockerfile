# Stage 1: Download all dependencies
FROM golang:1.26-alpine AS builder

WORKDIR /usr/local/go/src/github.com/opentibiabr/login-server
COPY go.mod .
COPY go.sum .
COPY src ./src

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /bin/login-server ./src/

FROM alpine:3.22

# Copy our static executable.
COPY --from=builder /bin/login-server /bin/login-server

RUN mkdir -p /app/logs && chown -R 65532:65532 /app
WORKDIR /app
USER 65532:65532

ENTRYPOINT ["/bin/login-server"]

