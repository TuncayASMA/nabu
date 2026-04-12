#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

run_client() {
  local output
  if ! output="$(timeout 30s go run ./cmd/nabu-client "$@" 2>&1)"; then
    echo "[dns-e2e] FAIL: nabu-client timed out or failed"
    echo "$output"
    exit 1
  fi
  printf '%s\n' "$output"
}

assert_json_any() {
  local output="$1"
  local filter="$2"
  local message="$3"
  if ! printf '%s\n' "$output" | jq -s -e "$filter" >/dev/null; then
    echo "[dns-e2e] FAIL: $message"
    echo "$output"
    exit 1
  fi
}

echo "[dns-e2e] package tests"
go test ./pkg/dns ./pkg/config >/dev/null

echo "[dns-e2e] secure DNS enabled (IPv4 rules)"
out_ipv4="$(run_client --serve-socks=false --dns-secure --dns-protocol=doh --dns-server=https://dns.example/dns-query --dns-timeout=5s)"
if ! grep -q "güvenli DNS yapılandırması etkin" <<<"$out_ipv4"; then
  echo "[dns-e2e] FAIL: secure DNS log not found"
  echo "$out_ipv4"
  exit 1
fi
assert_json_any "$out_ipv4" 'map(select(.leak_rules? == 2)) | length > 0' 'expected leak_rules=2'

echo "[dns-e2e] secure DNS enabled (IPv4+IPv6 rules)"
out_ipv6="$(run_client --serve-socks=false --dns-secure --dns-block-ipv6 --dns-protocol=doh --dns-server=https://dns.example/dns-query --dns-timeout=5s)"
assert_json_any "$out_ipv6" 'map(select(.leak_rules? == 4)) | length > 0' 'expected leak_rules=4'

echo "[dns-e2e] secure DNS disabled (normal mode)"
out_disabled="$(run_client --serve-socks=false --dns-secure=false)"
assert_json_any "$out_disabled" 'map(select(.dns? == "disabled")) | length > 0' 'expected dns=disabled summary'
if grep -q "güvenli DNS yapılandırması etkin" <<<"$out_disabled"; then
  echo "[dns-e2e] FAIL: secure DNS log should not appear when disabled"
  echo "$out_disabled"
  exit 1
fi

echo "[dns-e2e] PASS"
