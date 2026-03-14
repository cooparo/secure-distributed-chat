#!/bin/sh
set -e

echo "=== GRAT Docker Compose Test ==="
echo ""

# Build and start both nodes
echo "Building and starting nodes..."
docker compose up --build -d

# Wait for nodes to be ready
echo "Waiting for nodes to start..."
sleep 5

# Check that both containers are running
if ! docker compose ps --status running | grep -q node1; then
    echo "ERROR: node1 is not running"
    docker compose logs node1
    exit 1
fi
if ! docker compose ps --status running | grep -q node2; then
    echo "ERROR: node2 is not running"
    docker compose logs node2
    exit 1
fi

echo ""
echo "Both nodes are running."
echo ""

# Extract addresses
NODE1_ADDR=$(docker compose exec node1 gratcli identity -k /data/private.key 2>/dev/null | grep -oE '[A-Z2-7]{32}')
NODE2_ADDR=$(docker compose exec node2 gratcli identity -k /data/private.key 2>/dev/null | grep -oE '[A-Z2-7]{32}')

echo "Node 1 address: $NODE1_ADDR"
echo "Node 2 address: $NODE2_ADDR"
echo ""

echo "=== Usage ==="
echo ""
echo "Send a message from node1 to node2:"
echo "  docker compose exec node1 gratcli message -k /data/private.key -r $NODE2_ADDR -m 'hello from node1'"
echo ""
echo "Fetch messages on node2 from node1:"
echo "  docker compose exec node2 gratcli fetch -p $NODE1_ADDR"
echo ""
echo "View logs:"
echo "  docker compose logs -f"
echo ""
echo "Stop:"
echo "  docker compose down"
echo ""
echo "Stop and remove volumes:"
echo "  docker compose down -v"
