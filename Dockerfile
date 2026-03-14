# Stage 1: Build
FROM golang:1.25-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -buildmode=pie -trimpath -o /out/gratserver ./cmd/gratserver && \
    go build -buildmode=pie -trimpath -o /out/gratcli ./cmd/gratcli

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates sqlite3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/gratserver /usr/local/bin/gratserver
COPY --from=builder /out/gratcli /usr/local/bin/gratcli
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV XDG_DATA_HOME=/data
ENV XDG_RUNTIME_DIR=/run
ENV HOME=/root
WORKDIR /root

EXPOSE 1337

ENTRYPOINT ["docker-entrypoint.sh"]
