#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[preflight] missing command: $cmd"
    exit 1
  fi
}

echo "[preflight] checking required commands"
require_cmd go
require_cmd docker
require_cmd bash

echo "[preflight] checking docker compose files"
# Dummy PSK is only for compose schema validation; no container is started.
NABU_PSK=preflight-secret docker compose -f deploy/docker/docker-compose.yml config >/dev/null
docker compose -f deploy/docker/dns.docker-compose.yml config >/dev/null

echo "[preflight] checking systemd unit files"
for f in deploy/systemd/nabu-relay.service deploy/systemd/nabu-client.service; do
  if ! grep -q "^ExecStart=" "$f"; then
    echo "[preflight] invalid systemd unit, missing ExecStart: $f"
    exit 1
  fi
done
if ! grep -q -- "--relay-host=" deploy/systemd/nabu-client.service; then
  echo "[preflight] invalid nabu-client.service: --relay-host flag missing"
  exit 1
fi
if ! grep -q -- "--socks-listen=" deploy/systemd/nabu-client.service; then
  echo "[preflight] invalid nabu-client.service: --socks-listen flag missing"
  exit 1
fi

echo "[preflight] checking terraform syntax"
if command -v terraform >/dev/null 2>&1; then
  for d in deploy/terraform/oci deploy/terraform/hetzner; do
    terraform -chdir="$d" fmt -check >/dev/null
  done
else
  echo "[preflight] WARN: terraform bulunamadı, terraform syntax kontrolü atlandı"
fi

echo "[preflight] PASS"
