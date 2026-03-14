# GRAT (Gossip-based Ratchet Authenticated Transport)

A secure, distributed peer-to-peer chat system written in Go. Messages are encrypted end-to-end using the Signal Double Ratchet protocol with X25519 key exchange.

## Prerequisites

- [Go](https://go.dev/) 1.25+
- [GNU Make](https://www.gnu.org/software/make/)

Or alternatively:

- [Nix](https://nixos.org/) (for reproducible builds and dev shell)

## Installation

### Make

```sh
git clone https://github.com/cooparo/secure-distributed-chat && \
cd secure-distributed-chat && \
make
```

Binaries are placed in `bin/`.

### Nix

```sh
nix build
# Binaries in ./result/bin/

# Or run directly:
nix run .#gratserver
nix run .#gratcli
```

## Usage

### 1. Generate an identity

```sh
bin/gratcli identity -g -k private.key
```

### 2. Start the server

```sh
bin/gratserver -k private.key -v
```

The server listens on `[::]:1337` for peer connections and on a Unix socket for local CLI commands.

### 3. Send messages

```sh
bin/gratcli message -k private.key -r <PEER_ADDRESS> -m "hello"
```

### 4. Fetch messages

```sh
bin/gratcli fetch -p <PEER_ADDRESS>
```

### 5. Interactive TUI

```sh
bin/gratcli tui
```

If no identity key exists at the default path (`./private.key`), the TUI will automatically generate one on first launch.

Use `Tab` to switch between the contacts pane and chat pane, arrow keys to select a contact, and `Enter` to send a message. Your own address is filtered from the contacts list.

## Docker Compose (Two-Node Test Environment)

Docker Compose provides two isolated nodes on a shared network, solving the Unix socket and database conflicts that prevent running two instances locally.

### Quick start

```sh
docker compose up --build -d
docker compose logs
```

### Seed peer identities

Each node only knows itself at startup. To enable messaging, cross-seed their identities:

```sh
# Export each node's identity
NODE1_ROW=$(docker compose exec node1 sqlite3 /data/grat/db \
  "SELECT address, key_bundle, net_addr_bundle_time, net_addr_bundle FROM identities LIMIT 1;")
NODE2_ROW=$(docker compose exec node2 sqlite3 /data/grat/db \
  "SELECT address, key_bundle, net_addr_bundle_time, net_addr_bundle FROM identities LIMIT 1;")

# Insert node2 into node1's DB and vice versa
docker compose exec node1 sqlite3 /data/grat/db \
  "INSERT INTO identities (address, key_bundle, net_addr_bundle_time, net_addr_bundle) VALUES ($(echo "$NODE2_ROW" | awk -F'|' '{printf "'\''%s'\'', '\''%s'\'', %s, '\''%s'\''", $1, $2, $3, $4}'));"
docker compose exec node2 sqlite3 /data/grat/db \
  "INSERT INTO identities (address, key_bundle, net_addr_bundle_time, net_addr_bundle) VALUES ($(echo "$NODE1_ROW" | awk -F'|' '{printf "'\''%s'\'', '\''%s'\'', %s, '\''%s'\''", $1, $2, $3, $4}'));"
```

### Send and receive messages

The key is symlinked to the default path inside the containers, so `-k` is not needed:

```sh
# Get addresses
docker compose exec node1 gratcli identity
docker compose exec node2 gratcli identity

# Send from node1 to node2
docker compose exec node1 gratcli message -r <NODE2_ADDR> -m "hello from node1"

# Fetch on node2
docker compose exec node2 gratcli fetch -p <NODE1_ADDR>
```

### Use the TUI inside Docker

```sh
docker compose exec node1 gratcli tui
```

### Tear down

```sh
docker compose down       # Stop containers
docker compose down -v    # Stop and remove volumes (wipes keys and DB)
```

## Development

```sh
nix develop               # Enter dev shell with Go, sqlc, golangci-lint
make test                 # Run all tests
go test ./pkg/...         # Run tests for a specific subtree
```

SQL queries are generated via `sqlc`. After modifying files in `internal/database/queries/`, regenerate with:

```sh
sqlc generate
```
