#!/usr/bin/env bash
# Test: tunnel — client fetches nginx page through DNS tunnel.
# Usage: bash run.sh [record-type]
# Examples: bash run.sh          (defaults to txt)
#           bash run.sh cname
set -euo pipefail
cd "$(dirname "$0")"

RT="${1:-txt}"
if [ "$RT" = "txt" ]; then
    export RECORD_TYPE_FLAG=""
else
    export RECORD_TYPE_FLAG="-record-type $RT"
fi

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

echo "--- Building and starting services (record-type: $RT) ---"
docker compose up -d --build

echo "--- Waiting for tunnel (up to 30s) ---"
for i in $(seq 1 30); do
    if docker compose exec -T client wget -q -O- http://localhost:7000 2>/dev/null | grep -q "Welcome to nginx"; then
        echo ""
        echo "=== PASS ($RT) ==="
        exit 0
    fi
    printf "."
    sleep 1
done

echo ""
echo "--- Tunnel did not come up. Dumping logs ---"
docker compose logs client server
echo "=== FAIL ($RT) ==="
exit 1
