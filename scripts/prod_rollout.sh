#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[rollout] preflight"
./scripts/prod_preflight.sh

echo "[rollout] lint + unit + integration"
go vet ./...
go test -v -race -timeout 90s ./pkg/...
go test -v -race -timeout 120s ./test/integration/...

echo "[rollout] phase gates"
./test/e2e/phase2_closure_test.sh
./test/e2e/dns_leak_test.sh

echo "[rollout] build artifacts"
make build-all

echo "[rollout] docker build validation"
docker build --quiet -f deploy/docker/Dockerfile.relay -t nabu-relay:prod-check .
docker build --quiet -f deploy/docker/Dockerfile.client -t nabu-client:prod-check .

echo "[rollout] PASS"
echo "[rollout] next: deploy/docker or deploy/systemd akışını seçip canlıya al"
