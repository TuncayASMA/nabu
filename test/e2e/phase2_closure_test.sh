#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[phase2-closure] core package regression"
go test ./pkg/obfuscation ./pkg/phantom/... ./pkg/governor ./pkg/multipath

echo "[phase2-closure] integration regression"
go test ./test/integration -run 'Test(QUICRelay|WebSocketRelay|HTTPConnect|ProbeDefense)'

echo "[phase2-closure] PASS"
