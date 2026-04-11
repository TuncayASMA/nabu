# NABU Protocol Specification

**Version:** 2.6 (Faz 2 — Terraform Relay Provisioning)  
**Status:** Reference implementation complete; Faz 2 obfuscation + TLS + Anti-replay + DPI evasion + Multipath scheduling + Relay network + IaC provisioning operational  
**Module:** `github.com/TuncayASMA/nabu`

---

## Table of Contents

1. [Overview](#overview)
2. [Frame Wire Format](#frame-wire-format)
3. [Frame Flags](#frame-flags)
4. [Session Lifecycle](#session-lifecycle)
5. [Handshake & Key Exchange](#handshake--key-exchange)
6. [Encryption Layer](#encryption-layer)
7. [Data Transfer & Reliability](#data-transfer--reliability)
8. [RTT Measurement (Ping/Pong)](#rtt-measurement-pingpong)
9. [Stream Teardown](#stream-teardown)
10. [Rate Limiting](#rate-limiting)
11. [Transport Abstraction (Layer Interface)](#transport-abstraction-faz-2-prep)
12. [TCP Transport & HTTPConnect Obfuscation](#tcp-transport--httpconnect-obfuscation)
13. [TLS Wrapping (Faz 2 — DPI Evasion)](#tls-wrapping-faz-2--dpi-evasion)
14. [Anti-replay Window](#anti-replay-window)
15. [Security Considerations](#security-considerations)
16. [Salamander UDP Obfuscation](#16-salamander-udp-obfuscation)
17. [Probe Defense](#17-probe-defense)
18. [QUIC/H3 Transport](#18-quich3-transport)
19. [JA3/JA4 Fingerprint Normalization](#19-ja3ja4-fingerprint-normalization)
20. [Micro-Phantom Traffic Profile Engine](#20-micro-phantom-traffic-profile-engine)
21. [Governor Adaptive Rate Controller](#21-governor-adaptive-rate-controller)
22. [DPI Statistical Test Framework](#22-dpi-statistical-test-framework)
23. [nDPI + Suricata Integration Tests](#23-ndpi--suricata-integration-tests)
24. [Multipath QUIC Scheduler](#24-multipath-quic-scheduler)
25. [Relay Network Architecture](#25-relay-network-architecture)
26. [Terraform Relay Provisioning](#26-terraform-relay-provisioning)
27. [Changelog](#changelog)

---

## Overview

NABU uses a binary framing protocol carried over UDP.  A single UDP socket can
multiplex many logical streams via a 16-bit `StreamID`.  All application frames
are encrypted with AES-256-GCM once a session key has been established through
the X25519 Diffie-Hellman handshake.

```
  ┌────────────┐    UDP/443     ┌───────────────┐    TCP    ┌─────────────┐
  │ SOCKS5     │◄──────────────►│  NABU Relay   │◄─────────►│  Target     │
  │ Client     │  (AES-256-GCM) │  (udp_server) │           │  Server     │
  └────────────┘                └───────────────┘           └─────────────┘
```

The client side is embedded inside a SOCKS5 server.  Downstream SOCKS5 clients
(browsers, apps) connect to the local SOCKS5 listener; the tunnel code converts
each CONNECT request into a NABU stream towards the relay.

---

## Frame Wire Format

Every PDU is a fixed **12-byte header** followed by a variable-length payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────┬───────────────┬───────────────────────────────────┤
│    Version    │     Flags     │            StreamID               │
│   (1 byte)    │   (1 byte)    │           (2 bytes, BE)           │
├───────────────────────────────────────────────────────────────────┤
│                          Seq  (4 bytes, BE)                       │
├───────────────────────────────────────────────────────────────────┤
│                          Ack  (4 bytes, BE)                       │
├───────────────────────────────────────────────────────────────────┤
│                    Payload (0 – 65535 bytes)                      │
│                         ...                                       │
└───────────────────────────────────────────────────────────────────┘
```

| Field      | Offset | Size  | Description                                      |
|------------|--------|-------|--------------------------------------------------|
| `Version`  | 0      | 1 B   | Always `0x01` in this version                    |
| `Flags`    | 1      | 1 B   | Bitmask; see [Frame Flags](#frame-flags)          |
| `StreamID` | 2      | 2 B   | Big-endian logical stream identifier             |
| `Seq`      | 4      | 4 B   | Big-endian sender sequence number                |
| `Ack`      | 8      | 4 B   | Big-endian acknowledgment number                 |
| `Payload`  | 12     | 0–64k | Application data (may be AES-GCM ciphertext)    |

> **Payload length** is implicit: `len(UDP datagram) – HeaderSize`.  
> Maximum UDP payload advised: 1300 bytes to stay within typical MTUs.

---

## Frame Flags

```
Bit 7 (0x80)  FlagACK       — acknowledgment
Bit 6 (0x40)  FlagHandshake — PSK/X25519 key exchange
Bit 5 (0x20)  (reserved)
Bit 4 (0x10)  FlagPong      — RTT probe reply
Bit 3 (0x08)  FlagPing      — RTT probe request
Bit 2 (0x04)  FlagFIN       — stream teardown
Bit 1 (0x02)  FlagConnect   — new stream / SOCKS5 CONNECT
Bit 0 (0x01)  FlagData      — payload-carrying data frame
```

Flags can be combined:

| Combination              | Meaning                                       |
|--------------------------|-----------------------------------------------|
| `FlagHandshake`          | Client → Relay: initiate key exchange         |
| `FlagHandshake\|FlagACK` | Relay → Client: key exchange response         |
| `FlagConnect`            | Client → Relay: open stream to target         |
| `FlagACK`                | Any direction: acknowledge a sequence number  |
| `FlagData`               | Client ↔ Relay: application payload           |
| `FlagFIN`                | Either side: half-close / close               |
| `FlagFIN\|FlagACK`       | ACK for a received FIN                        |
| `FlagPing`               | Client → Relay: RTT probe                     |
| `FlagPong`               | Relay → Client: RTT probe reply               |

---

## Session Lifecycle

```
Client                                Relay
  │                                     │
  │── FlagHandshake (clientPub) ────────►│  X25519 keygen + HKDF
  │◄─ FlagHandshake|FlagACK (relayPub) ──│  session key stored
  │                                     │
  │── FlagPing (Seq=N) ─────────────────►│  RTT probe
  │◄─ FlagPong (Ack=N) ──────────────────│  echo Seq→Ack
  │  (measure elapsed time as RTT)       │
  │                                     │
  │── FlagConnect (Payload=host:port) ──►│  TCP dial to target
  │◄─ FlagACK (Ack=connectSeq) ──────────│
  │                                     │
  │── FlagData (Seq=i, Payload=bytes) ──►│  in-order delivery to target
  │◄─ FlagACK (Ack=i) ───────────────────│  stop-and-wait
  │                                     │
  │◄─ FlagData (Seq=j, Payload=bytes) ───│  relay → client (async)
  │── FlagACK (Ack=j) ──────────────────►│
  │                                     │
  │── FlagFIN (Seq=k) ──────────────────►│  client closes
  │◄─ FlagACK (Ack=k) ───────────────────│
  │                                     │
```

---

## Handshake & Key Exchange

NABU uses **X25519 Elliptic-Curve Diffie-Hellman** combined with a **Pre-Shared
Key (PSK)** to derive per-session AES-256-GCM keys.

### Step 1 — Client Hello

The client generates an ephemeral X25519 key pair and sends:

```
FlagHandshake
StreamID: <stream being opened>
Payload:  clientPublicKey  (32 bytes)
```

### Step 2 — Relay ACK

The relay generates its own ephemeral key pair, computes the shared secret:

```
sharedSecret = X25519(relayPrivate, clientPublic)
sessionKey   = HKDF-SHA256(
                 salt = PSK,
                 ikm  = sharedSecret,
                 info = clientPublicKey || relayPublicKey,
                 len  = 32 bytes
               )
```

Reply:

```
FlagHandshake | FlagACK
StreamID: <same>
Ack:      <incoming Seq>
Payload:  relayPublicKey  (32 bytes)
```

### Step 3 — Client Completes

The client computes the identical `sessionKey` using the relay's public key that
arrived in the ACK payload.  Both sides now share the same symmetric key.

> Without PSK the relay accepts connections in **unencrypted mode** (Payload
> empty in ACK, no frame encryption applied).

---

## Encryption Layer

All frames with `FlagHandshake == 0` and a non-empty payload are encrypted after
the handshake completes.

**Algorithm:** AES-256-GCM  
**Nonce:** 12-byte random prefix prepended to ciphertext  
**AAD:** none (current implementation)

```
ciphertext = AES-256-GCM-Seal(
    key   = sessionKey,
    nonce = random_12_bytes,
    plain = frame.Payload
)
wirePayload = nonce || ciphertext  // 12 + len(plain) + 16 bytes
```

Decryption on the receiving end strips the nonce prefix and opens the GCM tag.
Any frame that fails authentication is **silently discarded** (no error reply).

---

## Data Transfer & Reliability

NABU implements **stop-and-wait ARQ** per stream.

### Client → Target (via relay)

1. Client sends `FlagData` with monotonically increasing `Seq`.
2. Relay buffers out-of-order frames (reorder buffer, max 64 frames).
3. Relay delivers frames in order to the TCP target connection.
4. Relay sends `FlagACK` with `Ack = delivered_seq`.
5. Client retries if no ACK received within `baseTimeout` (exponential back-off
   up to `maxRTTBackoff = 4 s`).  After `maxSendRetries = 3` failures the
   stream is torn down.

### Target → Client (relay pushes)

The relay reads from the TCP target in a dedicated goroutine and pushes
`FlagData` frames to the client without waiting for ACKs (fire-and-forget at
relay level).

### Sequence Number Behaviour

- `CONNECT` frame uses `Seq = 1`.
- First `DATA` frame uses `Seq = 2` (i.e., `connectSeq + 1`).
- `Seq` wraps around naturally at `2^32`.
- Duplicate frames (already-delivered `Seq`) are ACK'd with the last
  in-order sequence number but not re-delivered to the target.

---

## RTT Measurement (Ping/Pong)

After the handshake the client measures the one-way trip time to calibrate
retry timeouts:

```
Client                         Relay
  │── FlagPing (Seq=N) ────────►│
  │         (t₀)                │
  │◄─ FlagPong (Ack=N) ──────────│
  │         (t₁)                │
  RTT = t₁ - t₀
  baseTimeout = max(100ms, min(4s, RTT × 2 + 50ms))
```

The relay echoes `Seq → Ack` in the Pong so the client can match the reply even
if other frames arrive in between.

---

## Stream Teardown

Either side can initiate teardown by sending `FlagFIN`.

```
Initiator           Responder
  │── FlagFIN ──────────►│
  │◄─ FlagACK ───────────│
  │                      │ (target TCP connection closed)
```

On relay shutdown (`SIGTERM` / context cancel) the relay sends `FlagFIN` to
every active stream's remote address before closing the UDP socket.

---

## Rate Limiting

The relay implements **token bucket** rate limiting per `(IP, port)` source.

- Default burst: `2 × RateLimitPPS`
- Tokens refill at `RateLimitPPS` tokens/second
- Frames that exceed the bucket are **silently dropped** (no RST sent)
- Drop count is tracked in `GlobalStats.DropsRL`

---

## Anti-replay Window

### Motivation

AES-256-GCM's nonce uniqueness provides implicit replay protection within a
single session: a replayed ciphertext is rejected with a tag mismatch.  However
this defence is insufficient in two scenarios:

1. **Unencrypted mode** — when no PSK is configured, frames carry no GCM tag.
2. **Session-level replay** — an attacker captures a full encrypted session and
   replays it using a re-obtained session key (e.g. after PSK rotation).

A dedicated sequence-number sliding window closes both gaps by tracking which
`Seq` values have already been processed and rejecting duplicates regardless of
encryption state.

### Algorithm

The relay maintains one **64-frame sliding window** per logical client
connection (TCP connection for TCPServer; source IP:port for UDPServer).

```
  high water mark
       │
       ▼
  front = highest accepted Seq + 1

  bitmap (64 bits)
  ┌────────────────────────────────────────────────────────────────┐
  │ bit 0 = (front-1)  bit 1 = (front-2)  …  bit 63 = (front-64) │
  └────────────────────────────────────────────────────────────────┘
       1 = already seen         0 = not yet seen
```

**Acceptance rules** (evaluated atomically under a mutex):

| Condition              | Action                                   |
|------------------------|------------------------------------------|
| `seq >= front`         | Accept; advance window; set bitmap bit   |
| `front-64 ≤ seq < front` | Accept only if bitmap bit is 0; set bit |
| `seq < front-64`       | Reject — too old (outside window)        |
| bitmap bit already set | Reject — replay detected                 |

**Window advance** — when a new `seq >= front` arrives, the bitmap is
left-shifted by `seq - front + 1` positions before setting bit 0. Shifts ≥ 64
reset the bitmap entirely (large-jump monotonic advance).

### Scope

| Component      | Granularity                   | Window lifecycle            |
|----------------|-------------------------------|-----------------------------|
| `TCPServer`    | Per TCP connection            | Lives for the duration of `handleConn`; discarded on disconnect |
| `UDPServer`    | Per source `IP:port`          | Stored in `replayWindows sync.Map`; reset on new handshake |

### Handshake Exemption

Frames with `FlagHandshake` are **exempt** from replay checking.  Handshake
frames carry ephemeral X25519 public keys; they are idempotent by design and
must succeed even after a client restart that resets its seq counter to 0.  A
new handshake also triggers a `Reset()` of the corresponding replay window so
that the fresh session can start numbering from 0.

### Implementation

```go
// pkg/relay/replay_window.go

type ReplayWindow struct {
    mu     sync.Mutex
    front  uint32   // highest accepted seq + 1
    bitmap uint64   // bit i = (front-1-i) seen
    ready  bool     // false until first Check call
}

func NewReplayWindow() *ReplayWindow
func (w *ReplayWindow) Check(seq uint32) bool  // true=accept, false=drop
func (w *ReplayWindow) Reset()                 // reset on new handshake
```

### Drop Behaviour

Replayed frames are **silently dropped** with a `WARN` log entry:

```
level=WARN msg="frame dropped: replay detected" remote=<addr> stream=<id> seq=<n>
```

No response is sent to the peer; this prevents oracle attacks that could be
used to probe which sequence ranges are cached in the relay's window.

---

## Security Considerations

| Threat                     | Mitigation                                              |
|----------------------------|---------------------------------------------------------|
| Passive traffic analysis   | AES-256-GCM encryption + ephemeral X25519 keys          |
| Replay attacks             | GCM nonce uniqueness **+ 64-frame seq sliding window** per connection |
| PSK brute-force            | Relay drops frames without a matching session silently   |
| SSRF / open-relay abuse    | Private/loopback destinations blocked by default        |
| DoS via packet flood       | Per-source token-bucket rate limiter                    |
| Forward secrecy            | Ephemeral X25519 keys — new key pair per connection      |
| Metadata leakage in errors | Error replies never sent; silent drop policy            |

> ~~**Known limitation (Faz 1):** No anti-replay window beyond GCM nonce
> uniqueness.  A dedicated sequence-number replay window is planned for Faz 2.~~
> **Resolved in Faz 2 (Oturum 1.24):** 64-frame sliding window implemented in
> `pkg/relay/replay_window.go`; integrated into TCPServer and UDPServer.

---

## Transport Abstraction (Faz 2 Prep)

All tunnel logic in `pkg/tunnel` operates against the `transport.Layer`
interface rather than `*transport.UDPClient` directly.  This decouples the
framing protocol from the underlying transport so that Faz 2 obfuscation layers
(HTTP CONNECT, TLS camouflage, WebSocket wrapper, etc.) can be swapped in
without touching relay logic.

### Core Interface

```go
// Layer is implemented by any transport that can send/receive NABU frames.
type Layer interface {
    Connect() error
    Close() error
    SendFrame(f Frame) error
    ReceiveFrame() (Frame, error)
}
```

### Optional Capability Interfaces

The tunnel interrogates optional interfaces at runtime via type assertions:

```go
// ReadTimeoutSetter: implemented by UDPClient and any Layer that supports
// configurable per-call read deadlines.
type ReadTimeoutSetter interface {
    SetReadTimeout(d time.Duration)
}

// SessionKeySetter: implemented by UDPClient and any Layer that supports
// applying an AES-256-GCM session key derived from the X25519 handshake.
type SessionKeySetter interface {
    SetSessionKey(key []byte)
}

// RTTMeasurer: implemented by transports that support Ping/Pong RTT probing.
type RTTMeasurer interface {
    MeasureRTT(streamID uint16, seq uint32) (time.Duration, error)
}
```

Usage pattern in `performHandshake`:

```go
// Set a tighter timeout during handshake (optional capability).
if ts, ok := client.(transport.ReadTimeoutSetter); ok {
    ts.SetReadTimeout(defaultAckTimeout)
}
// ... X25519 key exchange ...
// Install the derived session key (optional capability).
if sk, ok := client.(transport.SessionKeySetter); ok {
    sk.SetSessionKey(derivedKey)
}
```

### Compile-Time Assertions

`pkg/transport/udp_client.go` enforces full interface compliance at build time:

```go
var _ Layer      = (*UDPClient)(nil)
var _ RTTMeasurer = (*UDPClient)(nil)
```

### Tunnel Entry Point

`pkg/tunnel/relay_handler.go` exposes a testable `runTunnel` function that
accepts any `transport.Layer`, making it straightforward to unit-test with mock
transports:

```go
func runTunnel(conn net.Conn, req socks5.Request, layer transport.Layer, psk []byte) error
```

`NewRelayHandler` wraps `runTunnel` with a concrete `*UDPClient` for production
use; future obfuscation wrappers will implement `Layer` and be plugged in here.

### Faz 2 Extension Points

To add a new transport (e.g., HTTP CONNECT camouflage):

1. Create `pkg/obfuscation/http_connect.go` implementing `transport.Layer`.
2. Optionally implement `ReadTimeoutSetter` / `SessionKeySetter` if needed.
3. Wire it in `NewRelayHandler` via a config flag — zero changes to tunnel logic.

---

## TCP Transport & HTTPConnect Obfuscation

*(Added in v1.2, Oturum 1.22)*

### Motivation

Deep Packet Inspection (DPI) systems can fingerprint UDP traffic patterns.
NABU v1.2 adds a TCP transport layer disguising NABU frames as HTTPS (port 443)
traffic by tunnelling them inside an HTTP CONNECT session.

### Architecture

```
  ┌──────────────┐  HTTP CONNECT  ┌─────────────────┐  TCP   ┌──────────────┐
  │ nabu-client  │◄───────────────►│  TCPServer      │◄──────►│  Target      │
  │ (HTTPConnect │  port 443      │  (pkg/relay)    │        │  (e.g.        │
  │  Layer)      │                │                 │        │   example.com)│
  └──────────────┘                └─────────────────┘        └──────────────┘
```

The **client side** is `pkg/obfuscation.HTTPConnect` — a `transport.Layer`
implementation that wraps a TCP connection.

The **relay side** is `pkg/relay.TCPServer` — a mirror of `UDPServer` that
accepts TCP connections instead of UDP datagrams.

### TCP Frame Framing

Because TCP is stream-oriented, each NABU frame is length-prefixed:

```
┌───────────────────────┬──────────────────────────┐
│   Length (4 bytes BE) │   Encoded Frame (N bytes) │
└───────────────────────┴──────────────────────────┘
```

- **Length**: 32-bit big-endian unsigned integer; value = `len(encoded frame)`
- **Encoded frame**: the same `transport.Frame` binary encoding as UDP, padded
  and encrypted identically

### HTTP CONNECT Preamble

When `AcceptHTTPConnect = true` on `TCPServer`, the relay expects the client to
send a standard HTTP CONNECT handshake before any NABU frames:

```
Client → Relay:
  CONNECT nabu.relay:443 HTTP/1.1\r\n
  Host: nabu.relay:443\r\n
  \r\n

Relay → Client:
  HTTP/1.1 200 Connection established\r\n
  \r\n
```

NABU frames follow immediately after this exchange. To a passive observer the
connection looks like a standard TLS tunnel (HTTPS proxying).

When `AcceptHTTPConnect = false` (default in tests), the relay accepts raw
length-prefixed NABU frames directly — useful for testing without a mock proxy.

### TCPServer Dispatcher

`TCPServer.handleConn` reads frames in a loop using the same flag-based dispatch
as `UDPServer`:

| Flag       | Handler            | Action                                           |
|------------|--------------------|--------------------------------------------------|
| HANDSHAKE  | `handleHandshake`  | X25519 DH key exchange → derive session key      |
| CONNECT    | `handleConnect`    | Dial target TCP; start `pipeTargetToClient` goroutine |
| DATA       | `handleData`       | Reorder buffer → write to target; send ACK       |
| FIN        | `closeStreamTCP`   | Close target conn; remove stream state           |

### Client-Side Configuration

```
nabu-client --obfuscation http-connect \
            --obfs-proxy <http-proxy-host>:<port> \
            --relay <relay-host>:<relay-tcp-port>
```

| Flag             | Default  | Description                               |
|------------------|----------|-------------------------------------------|
| `--obfuscation`  | `none`   | Transport obfuscation: `none`, `http-connect` |
| `--obfs-proxy`   | *(empty)*| HTTP CONNECT proxy (optional; empty = direct TCP to relay) |

### Relay-Side Configuration

```
nabu-relay --serve-tcp \
           --tcp-addr :8443 \
           --tcp-http-connect
```

| Flag                  | Default   | Description                              |
|-----------------------|-----------|------------------------------------------|
| `--serve-tcp`         | `false`   | Enable TCPServer alongside UDP relay     |
| `--tcp-addr`          | `:8443`   | TCP relay listen address                 |
| `--tcp-http-connect`  | `true`    | Require HTTP CONNECT preamble from client |

### Factory Pattern for SOCKS5 Integration

`tunnel.NewRelayHandlerWithFactory` creates a new `transport.Layer` per SOCKS5
session, which is required when the layer is a TCP connection (not mux-capable):

```go
srv.OnConnect = tunnel.NewRelayHandlerWithFactory(psk, func() (transport.Layer, error) {
    return obfuscation.NewLayer(obfuscation.ModeHTTPConnect, relayAddr, proxyAddr)
})
```

This is the correct approach for `http-connect` mode. `NewRelayHandlerWithLayer`
(pre-built single layer) is only appropriate for multiplexing-capable transports.

---

## TLS Wrapping (Faz 2 — DPI Evasion)

### Motivation

Although the NABU frame payload is already encrypted with AES-256-GCM, the
TCP stream itself is a custom binary protocol.  A stateful DPI firewall can
identify it as non-HTTPS by inspecting the first bytes.  Wrapping the TCP
connection with TLS 1.3 makes the entire session appear as ordinary HTTPS
traffic: the observer sees a valid TLS ClientHello followed by opaque
application data records — indistinguishable from an HTTPS(443) connection.

### Architecture

```
Client (nabu-client)          Relay (nabu-relay)
─────────────────             ─────────────────────────
tls.Dial(relayAddr)  ───TLS Handshake───►  tls.NewListener
                                ↓
                        (optional HTTP CONNECT)
                                ↓
                      [NABU length-prefix framing]
```

When `--tcp-tls` is enabled on the relay, every `Accept()`-ed connection is a
`*tls.Conn`. The rest of the dispatch pipeline (HTTP CONNECT handshake,
X25519 DH, AES-256-GCM encryption, frame framing) runs identically on top of
the TLS stream.

### Configuration

#### Relay-side flags (`nabu-relay`)

| Flag | Default | Description |
|------|---------|-------------|
| `--tcp-tls` | `false` | Wrap TCP relay with TLS 1.3 |
| `--tcp-cert` | `""` | PEM certificate file; if empty a self-signed cert is generated in memory |
| `--tcp-key` | `""` | PEM private key file; paired with `--tcp-cert` |

#### Self-signed Certificate

When `--tcp-cert` / `--tcp-key` are not provided, `relay.BuildTLSConfig` generates
a fresh ECDSA P-256 certificate on startup:

```
 Subject: CN=nabu-relay
 KeyUsage: DigitalSignature  ExtKeyUsage: ServerAuth
 Valid: -1h → +2y (from startup time)
```

The certificate is different on every restart.  In production, operators should
provide a real certificate (e.g. from Let's Encrypt) so that the SNI hostname
matches a legitimate domain.

### TLS Config Parameters

```go
tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS13,
}
```

TLS 1.3 is **mandatory** (`MinVersion: tls.VersionTLS13`).  This eliminates
acknowledgeable fingerprinting vectors present in TLS 1.2 (cipher suite ordering,
estension list).

### Client-side Integration

For test clients or custom client implementations, use `obfuscation.WrapConn`
to obtain a `transport.Layer` over an already-dialled `*tls.Conn`:

```go
tlsConn, err := tls.Dial("tcp", relayAddr, &tls.Config{
    InsecureSkipVerify: true, // only in tests; use trusted cert in prod
    MinVersion: tls.VersionTLS13,
})
layer := obfuscation.WrapConn(tlsConn) // transport.Layer with 4-byte length framing
```

### Per-stream Traffic Counters

`StreamState` now exposes atomic counters for per-stream byte tracking:

| Field | Type | Description |
|-------|------|-------------|
| `BytesIn` | `atomic.Int64` | Bytes written to target (client → target direction) |
| `BytesOut` | `atomic.Int64` | Bytes sent to client (target → client direction) |

These complement the server-wide `GlobalStats` counters and allow per-connection
observability without locks.

---


| Version | Oturum | Changes |
|---------|--------|---------|
| 1.0     | 1.16   | Initial specification: frame format, handshake, encryption, RTT, reliability, rate limiting |
| 1.1     | 1.20   | Added §11 Transport Abstraction (Layer interface, optional capabilities, Faz 2 extension points) |
| 1.2     | 1.22   | Added §12 TCP Transport & HTTPConnect Obfuscation; `TCPServer` relay; `NewRelayHandlerWithFactory` |
| 1.3     | 1.23   | Added §13 TLS Wrapping (`BuildTLSConfig`, self-signed cert); per-stream `BytesIn`/`BytesOut` in `StreamState`; `WrapConn`/`NewRawTCPLayer` helpers |
| 1.4     | 1.24   | Added §14 Anti-replay Window (`ReplayWindow` 64-frame sliding window); integrated into `TCPServer` + `UDPServer`; `HTTPConnect.RelayTLSConfig` client-side TLS dialer; `--obfs-tls`/`--obfs-tls-insecure` flags in `nabu-client` |
| 1.5     | 1.25   | Added §15 WebSocket Obfuscation (`WebSocketLayer`, RFC 6455 binary-frame tunnelling); `TCPServer.AcceptWebSocket`; `ModeWebSocket` factory; `--serve-ws`/`--ws-addr`/`--ws-tls`/`--ws-cert`/`--ws-key` flags in `nabu-relay`; WSS (WebSocket over TLS) support |
| 1.6     | 1.27   | Added §16 Salamander UDP Obfuscation (`SalamanderEncode`/`SalamanderDecode` in `pkg/crypto`); `UDPClient.SalamanderPSK`; `UDPServer.SalamanderPSK`; `NewRelayHandlerUDPSalamander`; `--salamander-psk` flags in `nabu-client` and `nabu-relay`; fixed `MeasureRTT` Salamander bypass |
| 1.7     | 1.28   | Added §17 Probe Defense (`ProbeDefense` struct in `pkg/relay`); HTTP method sniffing at connection start; decoy HTML server (fake blog); IP-level ban tracker with sliding window; `TCPServer.ProbeDefense` field; `--probe-defense` flag in `nabu-relay` |
| 1.8     | 1.29   | Added §18 QUIC/H3 Transport (`QUICServer` in `pkg/relay`, `QUICLayer` in `pkg/obfuscation`); NABU frames over QUIC streams (length-prefix framing); multi-stream multiplexing; `--serve-quic`/`--quic-addr`/`--quic-cert`/`--quic-key` flags in `nabu-relay`; `quic-go v0.59.0` dependency |

---

## §15 WebSocket Obfuscation

`WebSocketLayer` tunnels NABU frames inside RFC 6455 WebSocket binary frames,
making relay traffic indistinguishable from WebSocket application traffic.

### Wire Format

```
TCP stream → WS upgrade (HTTP 101) → WS binary frames
  Each WS frame payload = [4-byte BE length][NABU frame bytes]
```

The inner `[4-byte length][frame]` structure is identical to raw TCP transport
(§12), so all existing relay code works without changes when `AcceptWebSocket=true`.

### Client handshake

`WebSocketLayer.Connect()` performs:
1. TCP dial to `RelayAddr`
2. Optional TLS upgrade when `TLSConfig != nil` (WSS)
3. RFC 6455 HTTP Upgrade (`GET / HTTP/1.1`, `Upgrade: websocket`, random base64 key)
4. Validates `101 Switching Protocols` + `Sec-WebSocket-Accept`
5. Wraps conn with `wsConn` (transparent frame encode/decode)

### Server acceptance

Set `TCPServer.AcceptWebSocket = true`.  On each accepted connection the server:
1. Reads the `GET` upgrade request
2. Validates `Upgrade: websocket` + `Sec-WebSocket-Key`
3. Sends `HTTP/1.1 101 Switching Protocols` with `Sec-WebSocket-Accept`
4. Wraps conn with `wsConn` (server side, no masking required)

### Masking

Per RFC 6455 §5.1 client-to-server frames **must** be masked with a
cryptographically random 4-byte key.  Server-to-client frames are unmasked.
`wsConn` enforces this automatically based on the `isClient` flag.

### WSS (WebSocket Secure)

Set `WebSocketLayer.TLSConfig` to enable TLS before the WebSocket handshake.
On the relay side start a TLS listener and set `AcceptWebSocket = true`.
Use `--ws-tls --ws-cert path.pem --ws-key path.key` on `nabu-relay`; omitting
`--ws-cert`/`--ws-key` generates a self-signed certificate at startup.

---

## §16 Salamander UDP Obfuscation

Salamander wraps every outgoing UDP datagram in a per-frame authenticated
envelope so that each packet looks like uniformly random bytes to a passive
observer.  There is no static header, no plaintext flags, no recognisable
magic number — only the shared PSK allows the recipient to recover the inner
NABU frame.

### Motivation

Without Salamander the NABU UDP transport has a fixed 12-byte header that DPI
can fingerprint.  Salamander eliminates all observable structure at the UDP
payload level.  Because the salt is refreshed for every frame the stream also
resists statistical traffic analysis.

### Wire Format

```
+-------------------+--------------------+-------------------------------------+
|  Salt (8 bytes)   |  GCM Nonce (12 B)  |  AES-256-GCM ciphertext + tag (N+16)|
+-------------------+--------------------+-------------------------------------+
```

- **Salt**: cryptographically random, freshly generated per frame.
- **Nonce**: 12 bytes drawn from the output of HKDF (see below).
- **Ciphertext**: AES-256-GCM encryption of the inner NABU frame, appended with
  the standard 16-byte authentication tag.
- **Total overhead**: 8 + 12 + 16 = **36 bytes** per datagram.

### Key Derivation

A per-frame AES-256 key is derived using HKDF-SHA256:

```
frame_key = HKDF-SHA256(
    secret = PSK,
    salt   = random_salt_8_bytes,
    info   = "nabu-salamander-v1",
    length = 32,
)
```

The 12-byte GCM nonce is the first 12 bytes of a second HKDF expansion with
`info = "nabu-salamander-v1-nonce"`.

Fresh salt → fresh frame key → each datagram is cryptographically independent.

### Security Properties

| Property | Value |
|---|---|
| IND-CPA | ✔ (fresh key + nonce every frame) |
| Authentication | ✔ (AES-256-GCM 128-bit tag) |
| Replay protection | ✔ (inner NABU replay window still active) |
| Traffic fingerprinting | ✘ (salt+ciphertext look uniformly random) |
| Forward secrecy | ✘ (static PSK; ephemeral keys planned via ECDH) |

### API

```go
// pkg/crypto/salamander.go
const SalamanderOverhead = 36  // salt(8) + nonce(12) + GCM tag(16)

func SalamanderEncode(psk, payload []byte) ([]byte, error)
func SalamanderDecode(psk, packet []byte) ([]byte, error)
```

### Integration Points

| Component | Field | Effect |
|---|---|---|
| `transport.UDPClient` | `SalamanderPSK []byte` | Encodes every `SendFrame`; decodes every `ReceiveFrame` and `MeasureRTT` |
| `relay.UDPServer` | `SalamanderPSK []byte` | Decodes every incoming datagram in `ReadFrom`; encodes all outgoing frames via `sendFrame`/`sendHandshakeACK` |
| `tunnel.NewRelayHandlerUDPSalamander` | `salamanderPSK []byte` | Creates a per-SOCKS5-session `UDPClient` with PSK set |

### CLI Flags

```
nabu-client --salamander-psk <psk>   # UDP mode only; incompatible with --obfuscation
nabu-relay  --salamander-psk <psk>   # applied to the UDP relay listener
```

### Scope

Salamander is a **UDP-only** layer.  It wraps the outer datagram before it
leaves the host NIC and after it arrives.  The inner NABU frame structure
(version, flags, stream ID, seq, ack, payload) is unchanged.  AES-GCM session
encryption (`--psk`) operates on the payload inside the NABU frame and is
independent of Salamander — both can be active simultaneously for defence in
depth.

---

## §17 Probe Defense

Probe Defense makes the relay appear as an ordinary HTTPS/web server to any
active prober or censor that does not possess the client PSK.  It operates at
the TCP connection level, before any NABU frame parsing.

### Motivation

Active censors send HTTP/HTTPS probes to discovered relay IP:port combinations
to test whether the endpoint is a proxy.  Without probe defense the relay
returns TCP-level errors or silent drops that are fingerprint-able as
"not a web server".  With probe defense the relay responds with a plausible
HTTP/1.1 response, making it indistinguishable from a legitimate web host.

Repeat probers are banned at the IP level, reducing per-probe relay load and
limiting information leakage through timing of decoy responses.

### Algorithm

#### Step 1 — Connection sniff (pre-frame)

For every new TCP connection, the relay reads the first 4 bytes with a 3-second
deadline using `bufio.Reader.Peek`:

```
if bytes ∈ {"GET ", "POST", "HEAD", "CONN", "OPTI", "PUT ", "DELE", "PATC", "TRAC"}
    → serve_decoy(conn)
if timeout expires or read error
    → serve_decoy(conn)
else
    → proceed with NABU frame parsing
```

#### Step 2 — PSK auth failure (post-frame)

If a PSK is configured and the client sends a non-Handshake frame without
first completing the key exchange, the relay calls `ProbeDefense.HandleProbe`
instead of silently closing the connection.

#### Step 3 — Decoy response

`HandleProbe` reads the full HTTP request (if present) to determine the
requested path, then serves one of three static HTML pages:

| Path | Decoy page |
|------|------------|
| `/about` | "About Me" personal page |
| `/blog` | Blog post listing |
| `*` (default) | Homepage |

All responses carry standard headers mimicking nginx 1.24.0 with
`Content-Type: text/html; charset=utf-8` and `Connection: close`.

#### Step 4 — IP ban tracking

After serving any decoy (or dropping a connection that is already banned), the
prober's IP is recorded in a sliding-window counter:

```
if failures_in_window(ip) >= BanThreshold
    → ban(ip, BanDuration)
    → subsequent connections from ip are silently closed (no decoy response)
```

### Default Thresholds

| Parameter | Default | Description |
|-----------|---------|-------------|
| `BanThreshold` | 5 | Failures within `BanWindow` before ban |
| `BanWindow` | 5 min | Rolling window for failure counting |
| `BanDuration` | 30 min | How long a banned IP is silently dropped |

All thresholds are configurable via struct fields on `ProbeDefense`.

### API

```go
// pkg/relay/probe_defense.go

type ProbeDefense struct {
    BanThreshold int           // default 5
    BanWindow    time.Duration // default 5 min
    BanDuration  time.Duration // default 30 min
}

func NewProbeDefense() *ProbeDefense
func (pd *ProbeDefense) HandleProbe(conn net.Conn, reader *bufio.Reader)
func (pd *ProbeDefense) IsBanned(addr net.Addr) bool
func (pd *ProbeDefense) ResetBan(addr string)   // test helper

// IsHTTPMethodPrefix reports whether the first 4 bytes look like an HTTP
// method prefix ("GET ", "POST", "HEAD", "CONN", "OPTI", "PUT ",
// "DELE", "PATC", "TRAC").
func IsHTTPMethodPrefix(b []byte) bool
```

### Integration Points

| Component | Field | Effect |
|-----------|-------|--------|
| `relay.TCPServer` | `ProbeDefense *ProbeDefense` | Sniffs first 4 bytes; serves decoy on HTTP or timeout; bans repeat probers |
| `relay.WebSocketServer` (future) | `ProbeDefense *ProbeDefense` | Same — before WS upgrade |

### CLI Flag

```
nabu-relay --probe-defense   # enable ProbeDefense on TCP (and WS if --serve-ws)
```

### Security Notes

- The decoy pages are **static** — dynamic content (e.g., serving real blog
  posts from a database) would increase attack surface without censor-evasion
  benefit.
- The ban tracker runs **in-process** with no persistence.  A relay restart
  (or process recycle) clears all bans.  For long-lived deployments consider
  externalising ban state to Redis.
- `IsHTTPMethodPrefix` matches only 4-byte prefixes; it does **not** parse
  full HTTP.  A real HTTP parse happens inside `HandleProbe` via
  `http.ReadRequest` for path routing.
- Decrypt errors and replay-window violations do **not** currently trigger
  `HandleProbe`.  This is intentional: those are NABU-aware attacks and the
  silent close is more revealing than a decoy response.

---

## §18 QUIC/H3 Transport

QUIC transport enables NABU frames to be carried over QUIC streams, making
relay traffic indistinguishable from HTTP/3 application traffic.

### Motivation

TCP-based transports (TCPServer, HTTPConnect, WebSocket) are susceptible to
TCP-reset injection by firewalls.  QUIC runs over UDP, making TCP-level
interference impossible.  Additionally, QUIC's 0-RTT connection establishment
and built-in TLS 1.3 make it faster and more resistant to TLS fingerprinting.

NABU frames are carried inside QUIC bidirectional streams (one QUIC stream per
logical relay session).  Multiple sessions share a single QUIC connection,
reducing handshake overhead and improving multiplexing.

### Wire Protocol

Each QUIC stream carries NABU frames using the same 4-byte length-prefix
framing as TCPServer:

```
┌──────────────────┬───────────────────────────┐
│  Length (4 B BE) │  NABU Frame (N bytes)     │
└──────────────────┴───────────────────────────┘
```

### Session Lifecycle

```
Client                                     QUICServer
  │                                             │
  │  QUIC CONNECT (UDP + TLS 1.3 handshake)     │
  │──────────────────────────────────────────►  │
  │                                             │
  │  OpenStream()                               │
  │──────────────────────────────────────────►  │
  │                                             │
  │  FlagConnect (payload = "host:port")        │
  │──────────────────────────────────────────►  │
  │                              dial target    │
  │  FlagACK                                    │
  │◄──────────────────────────────────────────  │
  │                                             │
  │  FlagData          target TCP               │
  │──────────────────────────────────────────►  │──► write
  │                               read ◄──────  │
  │  FlagData (echo)                            │
  │◄──────────────────────────────────────────  │
  │                                             │
  │  FlagFIN                                    │
  │──────────────────────────────────────────►  │
  │             FlagFIN (from target EOF)       │
  │◄──────────────────────────────────────────  │
```

### ALPN

The TLS ALPN value `"nabu/1"` is advertised alongside `"h3"` so that passive
DPI sees a standard HTTP/3 endpoint.  A client without the PSK receives a
decoy response (if ProbeDefense is enabled) and cannot distinguish the relay
from an ordinary web server.

### Multiplexing

Multiple logical NABU sessions are multiplexed over a single QUIC connection
without head-of-line blocking (unlike TCP).  Each call to `QUICLayer.Connect()`
opens a new bidirectional QUIC stream on the shared `*quic.Conn`.

### API

```go
// pkg/relay/quic_server.go
const quicALPN = "nabu/1"

func NewQUICServer(listenAddr string, tlsConf *tls.Config, logger *slog.Logger) (*QUICServer, error)
func (s *QUICServer) Start(ctx context.Context) error

type QUICServer struct {
    ListenAddr          string
    TLSConfig           *tls.Config
    AllowPrivateTargets bool
    PSK                 []byte
    ProbeDefense        *ProbeDefense
    Stats               GlobalStats
}

// pkg/obfuscation/quic_layer.go
func NewQUICLayer(relayAddr string, tlsConf *tls.Config) *QUICLayer
func (q *QUICLayer) Connect() (net.Conn, error)
func (q *QUICLayer) SendFrame(f transport.Frame) error
func (q *QUICLayer) ReceiveFrame() (transport.Frame, error)
func (q *QUICLayer) Close() error
```

### CLI Flags

```
nabu-relay --serve-quic                  # enable QUIC relay (UDP)
           --quic-addr :4433             # listen address (default :4433)
           --quic-cert path.pem          # TLS cert; omit for self-signed
           --quic-key  path.key          # TLS key;  omit for self-signed
           --probe-defense               # also applies to QUIC streams
           --psk <key>                   # AES-256-GCM session key
```

### Security Properties

| Property | Value |
|---|---|
| TLS version | 1.3 (enforced) |
| ALPN | `"nabu/1"`, `"h3"` |
| Connection encryption | QUIC built-in (AES-128-GCM or ChaCha20-Poly1305) |
| Frame encryption | AES-256-GCM (optional PSK, same as TCPServer) |
| Replay protection | `ReplayWindow` per-stream |
| HOL blocking | None (QUIC stream multiplexing) |
| DPI fingerprint | Indistinguishable from HTTP/3 traffic |
| Active probing | ProbeDefense decoy (optional) |

---

## §19 JA3/JA4 Fingerprint Normalization

### Motivation

Deep Packet Inspection (DPI) engines can identify NABU/custom TLS clients by
their TLS ClientHello fingerprint (JA3 hash), which encodes cipher suites,
extensions, elliptic curves and point formats.  To evade this, NABU clients
impersonate well-known browsers by adopting their exact TLS handshake profile
via the [uTLS](https://github.com/refraction-networking/utls) library.

### JA3 Algorithm

JA3 produces a 32-character MD5 digest of the following fields extracted from
the TLS ClientHello, with all GREASE values (RFC 8701) excluded:

```
MD5( TLSVersion , CipherSuites , ExtensionIDs , NamedGroups , PointFormats )
```

Fields are dash-separated within each group and comma-separated between groups.

**GREASE detection** (RFC 8701):

```go
func isGREASEValue(v uint16) bool {
    return (v&0x0f0f == 0x0a0a) && (v>>8 == v&0xff)
}
// e.g. 0x0a0a, 0x1a1a, … 0xfafa → excluded
// 0x11ec (X25519MLKEM768) → NOT GREASE; included
```

### Browser Profiles

| Profile | uTLS ID | JA3 Hash | Cipher String Deterministic? | Hash Deterministic? |
|---------|---------|----------|------------------------------|---------------------|
| Chrome 133 | `HelloChrome_133` | varies | ✅ | ❌ (ShuffleChromeTLSExtensions) |
| Firefox 120 | `HelloFirefox_120` | `7fbdc1beb9b27dfb24f94e3a7f2112af` | ✅ | ✅ |
| Edge 85 | `HelloEdge_85` | varies | ✅ | ❌ |
| Random | `HelloRandomized` | N/A | ❌ | ❌ |

> **Chrome Extension Shuffle**: `HelloChrome_133` calls `ShuffleChromeTLSExtensions()`
> internally (uTLS mimics Chrome's anti-fingerprinting randomization).  The
> cipher suite ordering remains fixed, so `ComputeJA3CipherString` is always
> deterministic for Chrome; the full JA3 hash is not.

### Validated Cipher Strings

```
Chrome 133:  4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53
Firefox 120: 4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53
```

### API Reference

```go
// pkg/obfuscation/ja3_normalizer.go

type Profile int

const (
    ProfileChrome  Profile = iota // Chrome 133 (HelloChrome_133)
    ProfileFirefox                // Firefox 120 (HelloFirefox_120)
    ProfileEdge                   // Edge 85 (HelloEdge_85)
    ProfileRandom                 // HelloRandomized
)

// ComputeJA3String returns the full JA3 string for a ClientHelloSpec,
// excluding GREASE values.
func ComputeJA3String(spec *utls.ClientHelloSpec) string

// ComputeJA3CipherString returns only the cipher-suite field of the JA3
// string.  Always deterministic even for Chrome (only extensions are shuffled).
func ComputeJA3CipherString(spec *utls.ClientHelloSpec) string

// ComputeJA3Hash returns MD5(ComputeJA3String(spec)) as a hex string.
func ComputeJA3Hash(spec *utls.ClientHelloSpec) string

// GetProfileSpec returns the ClientHelloSpec for the given Profile.
// Calls utls.UTLSIdToSpec internally.
func GetProfileSpec(p Profile) (*utls.ClientHelloSpec, error)

// ValidateProfileJA3 checks the computed JA3 hash against the expected value
// in ExpectedJA3Hash.  Returns nil if no expected hash is registered (e.g.
// Chrome, Random) or if the hashes match.
func ValidateProfileJA3(p Profile) error

// UTLSDialNormalized opens a TLS connection to addr using the given Profile
// and timeout.  Returns the raw net.Conn after TLS handshake.
func UTLSDialNormalized(addr string, cfg *utls.Config, profile Profile, dialTimeout time.Duration) (net.Conn, error)

// ProfileFromName converts a string name ("chrome","firefox","edge","random")
// to Profile.
func ProfileFromName(name string) (Profile, error)

// ProfileName returns the canonical name for a Profile.
func ProfileName(p Profile) string
```

### Security Properties

| Property | Value |
|---|---|
| TLS version | 1.3 (enforced by browser profile) |
| Cipher suites | Browser-identical (no custom suites) |
| Extension order | Browser-identical for Firefox/Edge; randomized for Chrome (matches real Chrome behavior) |
| JA3 fingerprint | Matches target browser profile |
| GREASE support | Full RFC 8701 GREASE injection (excluded from JA3 hash) |
| DPI evasion | ClientHello indistinguishable from real browser traffic |

---

## §20 Micro-Phantom Traffic Profile Engine

### Motivation

Passive DPI (Deep Packet Inspection) systems can detect tunnels not only by
packet content (already addressed by AES-256-GCM + TLS) but by behavioural
features: inter-arrival times (IAT), packet-size distributions, burst patterns,
and session durations.  The Micro-Phantom engine shapes NABU traffic to match
statistical profiles of real, popular application traffic, making per-flow
behaviour indistinguishable from organic CDN/OTT flows.

### Built-in Profiles

| Profile Name | Traffic Class | Packet Size Bias | IAT Bias | Burst (min/max pkts) | Session Mean |
|---|---|---|---|---|---|
| `web_browsing` | HTTP/2 browsing | bimodal (40B ACKs + 1400B data) | 30–60 ms | 3 / 15 | 60 s |
| `youtube_sd` | DASH SD video | large frames (1000–1460 B) | 10–30 ms | 20 / 60 | 600 s |
| `instagram_feed` | API + media scroll | mixed (100B API + 1300B media) | 100–200 ms (human pace) | 5 / 25 | 180 s |

Custom profiles can be loaded from JSON files at runtime via `LoadFromFile`.

### CDF Sampling Algorithm

Each profile stores two 20-point Cumulative Distribution Function (CDF) arrays:
`PacketSizeDist` (over `[0, MaxPacketBytes=1460]` bytes) and `IATDist` (over
`[0, MaxIATMs=200]` ms).  Sampling uses inverse-transform sampling:

```
for i, v in enumerate(cdf):
    if u <= v:
        return round(maxVal * (i+1) / len(cdf))
return maxVal
```

where `u ~ Uniform(0,1)`.  This produces integer values in `[1, maxVal]` with
the distribution encoded by the CDF table.

CDF validity constraints enforced by `Validate()`:
- Length must equal `cdfPoints` (20)
- Values must be strictly non-decreasing
- Terminal value must equal 1.0 ± 1e-9
- Profile name must be non-empty

### Token-Bucket Rate Shaper

The `Shaper` type wraps any `net.Conn` and enforces:

1. **Packet sizing** — each logical write is split into segments whose sizes are
   sampled from the profile's `PacketSizeDist`.  Segments smaller than the
   original payload are zero-padded to the sampled size to preserve the wire
   distribution.
2. **Inter-arrival timing** — between consecutive segments the goroutine sleeps
   for a duration sampled from `IATDist` (converted to nanoseconds).
3. **Token-bucket rate limit** — an internal `tokenBucket` (capacity ≥ 2 ×
   MaxPacketBytes) enforces a per-connection rate ceiling (default: 10 MiB/s);
   blocking is context-aware.
4. **Idle traffic generation** — `GenerateIdle(ctx, duration)` emits synthetic
   zero-entropy (all-zeros) segments at the profile IAT rate, sustaining the
   expected flow statistics between real application bursts.

### Go API Reference

```go
// --- pkg/phantom/profiles ---

// TrafficProfile describes the statistical fingerprint of a traffic class.
type TrafficProfile struct {
    Name            string
    PacketSizeDist  []float64   // 20-point CDF over [0, MaxPacketBytes]
    IATDist         []float64   // 20-point CDF over [0, MaxIATMs] ms
    BurstPattern    BurstModel
    SessionDuration Distribution
    DNSPatterns     []string
}

// Validate returns an error if the profile is malformed.
func (p *TrafficProfile) Validate() error

// SamplePacketSize returns a packet size in [1, MaxPacketBytes].
func (p *TrafficProfile) SamplePacketSize(rng *rand.Rand) int

// SampleIATMs returns an inter-arrival time in [0, MaxIATMs] ms.
func (p *TrafficProfile) SampleIATMs(rng *rand.Rand) float64

// LoadEmbedded loads one of the built-in profiles by name.
func LoadEmbedded(name string) (*TrafficProfile, error)

// LoadFromFile loads a JSON-serialised profile from disk.
func LoadFromFile(path string) (*TrafficProfile, error)

// EmbeddedNames returns the list of built-in profile names.
func EmbeddedNames() []string

// --- pkg/phantom/shaper ---

// Shaper is a net.Conn wrapper that shapes traffic to match a TrafficProfile.
type Shaper struct { /* ... */ }

// New creates a Shaper.  conn and profile must be non-nil and profile must
// pass Validate().  Zero Options fields are filled with defaults.
func New(conn net.Conn, profile *TrafficProfile, opts Options) (*Shaper, error)

// Write splits b into profile-sized segments and emits them with profile
// IAT delays.
func (s *Shaper) Write(b []byte) (int, error)

// GenerateIdle emits synthetic traffic for up to duration (or ctx cancel).
func (s *Shaper) GenerateIdle(ctx context.Context, duration time.Duration) error

// SetProfile hot-swaps the active traffic profile (thread-safe).
func (s *Shaper) SetProfile(p *TrafficProfile) error

// Profile returns the currently active TrafficProfile.
func (s *Shaper) Profile() *TrafficProfile
```

### Security Properties

| Property | Value |
|---|---|
| Payload entropy | Unchanged (AES-GCM ciphertext) |
| Packet-size distribution | Profile CDF (DPI-resistant) |
| IAT distribution | Profile CDF (DPI-resistant) |
| Burst pattern | Profile BurstModel |
| Idle cover traffic | Zero-entropy synthetic segments |
| Rate control | Token-bucket, context-cancellable |
| Hot profile swap | Supported (atomic pointer update) |

---

## §21 Governor Adaptive Rate Controller

### Motivation

Even a perfectly obfuscated tunnel becomes detectable if its bandwidth is
constant at all hours: real CDN-delivered traffic has a strong diurnal rhythm
(low at 08:00, peaking around 20:00 in the evening prime-time).  The Governor
matches this rhythm by scaling the tunnel's target bandwidth with a
time-of-day coefficient, making NABU's per-connection rate statistically
indistinguishable from background internet traffic on the same interface.

### Time-of-Day Coefficient

The coefficient `c(h) ∈ [0.30, 1.00]` is a truncated cosine:

```
raw(h) = 0.5 × (1 − cos(2π × (h − 8) / 24))    h ∈ [0, 24)
c(h)   = clamp(raw(h), 0.30, 1.00)
```

Key values:

| Hour | raw | c(h) | Description |
|------|-----|------|-------------|
| 08:00 | 0.00 | 0.30 | Morning trough (clamped floor) |
| 12:00 | 0.50 | 0.50 | Midday |
| 20:00 | 1.00 | 1.00 | Prime-time peak |
| 00:00 | ~0.75 | 0.75 | Late night — still active |

### Architecture (Faz 2 — non-eBPF)

```
/proc/net/dev  ──►  ReadProcNetDev()  ──►  Snapshot
                                              │
                              ComputeThroughput(prev, cur)
                                              │
                                    c(h) = TimeOfDayCoeff(now)
                                              │
                              TargetBytesS = MaxBandwidthBps × c(h)
                                              │
                              Recommendation ──► channel ──► Shaper
```

The `Governor` struct wraps this loop: it spawns a goroutine that reads
`/proc/net/dev` every `PollInterval` (default 2 s), computes interface
throughput, applies the TOD coefficient, and emits a `Recommendation` on
a buffered channel.  The associated `Shaper` (§20) reads this channel and
adjusts its token-bucket rate accordingly.

The `NowFunc` field enables deterministic testing without wall-clock
dependency.

### Go API Reference

```go
// pkg/governor

// TimeOfDayCoeff returns c(h) ∈ [0.30, 1.00] for the given time.
func TimeOfDayCoeff(t time.Time) float64

// ReadProcNetDev parses /proc/net/dev and returns per-interface counters.
func ReadProcNetDev(path string) (map[string]InterfaceStats, error)

// ComputeThroughput computes bytes/s between two Snapshots.
func ComputeThroughput(a, b Snapshot) []ThroughputBps

// Governor watches /proc/net/dev and emits adaptive Recommendations.
type Governor struct { /* ... */ }

func New(cfg Config) *Governor
func (g *Governor) Run(ctx context.Context) <-chan Recommendation
func (g *Governor) LastRecommendation() *Recommendation

type Recommendation struct {
    TargetBytesS     float64   // suggested bandwidth (bytes/s)
    TODCoeff         float64   // time-of-day multiplier applied
    ObservedRxBytesS float64   // interface receive throughput
    ObservedTxBytesS float64   // interface transmit throughput
    At               time.Time // computation timestamp
}
```

### Security Properties

| Property | Value |
|---|---|
| Rate scaling | Time-of-day cosine, peak at 20:00 |
| Floor | 0.30 × MaxBandwidthBps (avoids hard cutoffs) |
| Counter wrap | Treated as 0 bytes/s (conservative) |
| eBPF upgrade path | Faz 3 Sprint 17–18 (kernel hook for exact flow accounting) |
| /proc access | Read-only, unprivileged |

---

---

## 22. DPI Statistical Test Framework

The Micro-Phantom shaper must produce traffic that is statistically
indistinguishable from the declared `TrafficProfile` CDF. Two complementary
tests are provided in `pkg/phantom/stat/` and `test/dpi/`.

### 22.1 Kolmogorov-Smirnov Test (`KSTest`)

The one-sample KS test compares an empirical distribution against a reference
CDF. The implementation uses the asymptotic Kolmogorov distribution to derive
a p-value:

```
D   = max|F_empirical(x) − F_reference(x)|  over all observed x
t   = D · √n
p   ≈ 2 · Σ_{k=1}^{∞} (−1)^{k−1} · exp(−2k²t²)
```

A p-value > 0.05 indicates that the sample is compatible with the reference
CDF at the 5 % significance level.  The series converges in ≤ 20 terms for
all practical values of D and n.

The reference CDF is evaluated via piecewise-linear interpolation over the
20-bucket profile CDF. This is suitable for the KS test on **continuous**
distributions (e.g., IAT from `SampleIATMs`).

### 22.2 Bucket Frequency Test (`BucketFrequencyTest`)

For the **discrete** packet-size distribution (output of `SamplePacketSize`),
an empirical KS test is prone to systematic over-rejection because the sampler
returns values within fixed integer buckets rather than a truly continuous
range.  The `BucketFrequencyTest` function avoids this by comparing per-bucket
observed probability against expected probability with a configurable relative
tolerance (default 60 %):

```
For each bucket i:
    expected_p[i] = CDF[i] − CDF[i−1]
    observed_p[i] = count(sample in bucket i) / total
    PASS if |observed_p[i] − expected_p[i]| / expected_p[i] ≤ tolerance
         or expected_p[i] < 0.01 (skip sparse buckets)
```

### 22.3 Shannon Entropy

The `ShannonEntropy` function computes the binary (base-2) Shannon entropy of
a byte stream:

```
H = −Σ_{b=0}^{255} p(b) · log₂(p(b))
```

For AES-GCM ciphertext, H ≈ 8 bits/byte.  For unencrypted but shaped data
through a `Shaper` (which pads and reorders but does not encrypt), H is
typically 5–7 bits/byte depending on payload distribution.  A minimum
threshold of 3 bits/byte is asserted in the integration test to detect
degenerate or stripped traffic.

### 22.4 Test Inventory

| Package | Test | What is verified |
|---------|------|------------------|
| `pkg/phantom/stat` | `TestKSTest_SameDistribution` | p > 0.05 for n=500 uniform sample vs uniform CDF |
| `pkg/phantom/stat` | `TestKSTest_DifferentDistribution` | p < 0.05 when sample is constant (all 0.99) |
| `pkg/phantom/stat` | `TestBucketFrequencyTest_Uniform` | bucket counts within 50% of expected for uniform |
| `pkg/phantom/stat` | `TestShannonEntropy_Random` | H ≥ 7.8 bits for pseudo-random bytes |
| `test/dpi` | `TestProfile_*_PacketSizeDist` | 3 built-in profiles: bucket frequency within 60% |
| `test/dpi` | `TestProfile_*_IATDist` | 3 built-in profiles: IAT bucket frequency within 60% |
| `test/dpi` | `TestPhantomShaper_ShannonEntropy` | 32 KB shaped data: H ≥ 3.0 bits/byte |

---

## 23 nDPI + Suricata Integration Tests

### 23.1 nDPI Classification (`test/dpi/ndpi_test.go`)

Traffic is written as a PCAP file (pure Go, no CGO) and analysed offline by
`ndpiReader` (libndpi-bin ≥ 4.2, ARM64 apt package):

| Test | Input | Expected classification |
|------|-------|------------------------|
| `TestNDPI_TLSClientHello` | 5 × TLS 1.3 ClientHello packets (port 443) | TLS |
| `TestNDPI_PhantomShapedTraffic` | 32 KB Phantom-shaped data wrapped as TLS AppData | TLS |

PCAP packets are hand-crafted in Go (Ethernet + IPv4 + TCP, checksums=0 accepted
by nDPI in file mode).  Skip condition: `ndpiReader` not present in PATH.

### 23.2 Suricata Zero-Alert Test (`test/dpi/suricata_test.go`)

Suricata 8.x runs via `jasonish/suricata:latest` Docker image in offline
PCAP-read mode (`-r`).  Five local rules (SID 9000001–9000005) check for
OpenVPN, WireGuard, SSH, Shadowsocks, and Tor patterns.

| Test | Assertion |
|------|----------|
| `TestSuricata_ZeroAlertsOnTLS` | 27-packet Phantom TLS pcap → **0 alerts** |
| `TestSuricata_PositiveControl` | SSH banner packet → SID 9000003 fires (rule set verified) |

Skip condition: `jasonish/suricata` image not present on local Docker daemon.

### 23.3 Custom Suricata Rule Set

```
SID 9000001 — OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 (byte 0x38)
SID 9000002 — WireGuard handshake (byte 0x01, port 51820)
SID 9000003 — SSH banner "SSH-" (port 22)
SID 9000004 — Shadowsocks on port 8388
SID 9000005 — SOCKS5 proxy greeting on Tor port 9050
```

### 23.4 PCAP Construction (pure Go)

No third-party PCAP library (no CGO, no gopacket) is required.  Frames are
built manually:

```
writePcapGlobalHeader() — 24-byte PCAP file header (magic=0xa1b2c3d4, linktype=1)
writePcapRecord()       — 16-byte per-record header + frame bytes
buildEthernetFrame()    — Ethernet (14 B) + IPv4 (20 B) + TCP (20 B) + payload
tlsClientHello()        — TLS 1.3 ContentType=0x16, HandshakeType=0x01, SNI=example.com
```

Checksums are zeroed; both nDPI (`-k none` implicit in file mode) and Suricata
(`-k none` flag) skip checksum validation, so frames parse correctly.

---

## 24 Multipath QUIC Scheduler

The multipath scheduler layer (`pkg/multipath`) provides path-selection
algorithms for distributing NABU streams across multiple simultaneous network
paths (e.g., OCI FR + Hetzner DE relays).

### 24.1 PathStats

```go
type PathStats struct {
    ID        uint32        // opaque path identifier
    RTT       time.Duration // smoothed RTT
    Bandwidth uint64        // estimated bytes/second
    LossRate  float64       // packet loss fraction [0,1]
    InFlight  uint64        // unacknowledged bytes on this path
    Available bool          // path is currently usable
}
```

### 24.2 Scheduler Interface

```go
type Scheduler interface {
    SelectPath(paths []PathStats) int  // returns index, -1 if none available
}
```

All implementations are safe for concurrent use.

### 24.3 MinRTTScheduler

Selects the available path with the lowest EWMA-smoothed RTT.
Default smoothing factor α = 0.125 (matches QUIC RFC 9002 §A.2).

$$\text{EWMA}_{n} = \text{EWMA}_{n-1} + \alpha \cdot (\text{RTT}_n - \text{EWMA}_{n-1})$$

On ties the lower-indexed path wins (stable ordering).

### 24.4 BLESTScheduler

Blocking Estimation Scheduler (Lim & Ott, 2014).  Penalises paths whose
estimated queue depth exceeds `blestMaxQueue` (50 ms):

$$\text{score} = \frac{\text{RTT}_{\text{EWMA}}}{1 - \text{LossRate}} + \lambda \cdot \max(0,\; \text{queueDepth} - Q_{\max})$$

where $\text{queueDepth} = \text{InFlight} / \text{Bandwidth}$ (seconds) and
$\lambda = 1.0$.  The path with the lowest score is selected.

### 24.5 RedundantScheduler

Duplicates critical frames across all available paths (up to `MaxCopies`).
Exposes both `SelectPath` (tie-breaks via embedded MinRTT) and
`SelectAllPaths` returning all available path indices.

### 24.6 WeightedRRScheduler

Deficit-based weighted round-robin.  Each path is credited
$\text{bandwidth}_i / \sum \text{bandwidth}_j$ per scheduling round;
the path with the highest accumulated credit is chosen and debited 1.0.

### 24.7 Test Summary

| Test | Scheduler | Assertion |
|------|-----------|-----------|
| `TestMinRTT_SelectsLowestRTT` | MinRTT | Index with smallest RTT wins |
| `TestMinRTT_SkipsUnavailable` | MinRTT | Unavailable paths excluded |
| `TestMinRTT_AllUnavailable` | MinRTT | Returns -1 |
| `TestMinRTT_EmptyPaths` | MinRTT | Returns -1 for nil input |
| `TestMinRTT_EWMASmooths` | MinRTT | EWMA converges after 20 rounds |
| `TestMinRTT_SinglePath` | MinRTT | Returns 0 for single path |
| `TestBLEST_SelectsLowQueuePath` | BLEST | High-queue path penalised |
| `TestBLEST_FallbackToMinRTTWhenQueuesEqual` | BLEST | Low RTT wins when queues equal |
| `TestBLEST_SkipsUnavailable` | BLEST | Unavailable paths excluded |
| `TestBLEST_AllUnavailable` | BLEST | Returns -1 |
| `TestBLEST_LossAdjustedRTT` | BLEST | 90% loss path loses to 30ms clean path |
| `TestRedundant_SelectAllPaths` | Redundant | All available indices returned |
| `TestRedundant_MaxCopiesCaps` | Redundant | Capped at MaxCopies=2 |
| `TestRedundant_SelectPathDelegatesToPrimary` | Redundant | Primary MinRTT used |
| `TestRedundant_NoPaths` | Redundant | Empty/nil edge cases |
| `TestWeightedRR_HighBandwidthWinsMore` | WRR | 3:1 bandwidth → ~75:25 split in 400 rounds |
| `TestWeightedRR_SkipsUnavailable` | WRR | Always selects available path |
| `TestWeightedRR_AllUnavailable` | WRR | Returns -1 |
| `TestWeightedRR_ZeroBandwidth` | WRR | Treats 0 BW as 1 byte/s (no panic) |

All 19 tests pass with `-race`.

---

## 25 Relay Network Architecture

### 25.1 Topology

```
Client ──┬──> nabu-relay-fr (OCI FR / Marseille,   path-id=0, port 7001)
         └──> nabu-relay-de (Hetzner DE / Falkenstein, path-id=1, port 7002)
                   └──> exit-relay → Internet
```

Each relay runs the NABU relay binary in a Docker container. The client-side
`MultiPathConn` maintains live `PathStats` for both paths and switches
automatically based on the active `Scheduler`.

### 25.2 MultiPathConn (`pkg/multipath/conn.go`)

Manages per-path lifecycle: background UDP echo probes, stats update, and
scheduler-driven path selection.

| Component | Description |
|-----------|-------------|
| `RelayEndpoint` | `{ID uint32, Addr string}` — identifies a relay |
| `PingOptions` | `Interval` (5 s), `Timeout` (2 s), `ProbesPerRound` (3) |
| `Start(ctx)` | Launch per-path probe goroutines (idempotent) |
| `Stop()` | Cancel + WaitGroup drain |
| `SelectPath()` | Scheduler-driven, returns `(int, RelayEndpoint)` |
| `UpdateStats()` | External push from QUIC ACK callbacks |
| `Stats()` | Snapshot of current `[]PathStats` |

**Probe port convention:** `probe_port = relay_port + 1000`

UDP echo payload is 8 bytes: `{0x4E, 0x41, 0x42, 0x55, 0x50, 0x52, 0x01, 0x02}`
(ASCII `NABUPR` + version bytes). A path is marked `Available=true` as soon as
any probe round succeeds; it stays unavailable if all `ProbesPerRound` probes
time out.

### 25.3 Docker Compose (`deploy/docker/relay-network.yml`)

Three services on bridge network `nabu-mp-net`:

| Service | Region | Port | Env |
|---------|--------|------|-----|
| `nabu-relay-fr` | OCI FR / Marseille | 7001 | `NABU_PATH_ID=0` |
| `nabu-relay-de` | Hetzner DE / Falkenstein | 7002 | `NABU_PATH_ID=1` |
| `nabu-client-mp` | client | — | `NABU_SCHEDULER` |

`NABU_SCHEDULER` accepts: `minrtt` \| `blest` \| `redundant` \| `weightedrr`

### 25.4 Test Summary (13 tests, all PASS with `-race`)

| Test | Assertion |
|------|-----------|
| `TestDeriveProbeAddr_Basic` | `7001` → `8001` |
| `TestDeriveProbeAddr_IPv6` | `[::1]:7002` → `[::1]:8002` |
| `TestDeriveProbeAddr_BadAddr` | error returned for malformed addr |
| `TestMultiPathConn_InitialStats` | all paths unavailable, RTT=10 s sentinel |
| `TestMultiPathConn_UpdateStats` | RTT/BW/loss updated, `Available=true` |
| `TestMultiPathConn_UpdateStats_OutOfRange` | no panic for index −1 or 99 |
| `TestMultiPathConn_SelectPath_PreferLowRTT` | low-RTT path wins (20 ms < 80 ms) |
| `TestMultiPathConn_SelectPath_NoneAvailable` | returns −1, empty endpoint |
| `TestMultiPathConn_SelectPath_Empty` | nil endpoints → −1 |
| `TestMultiPathConn_ProbeReachable` | real UDP echo server → `Available=true` |
| `TestMultiPathConn_ProbeUnreachable` | port 59 999 → `Available=false` |
| `TestMultiPathConn_StartIdempotent` | double `Start` is no-op |

---

## 26 Terraform Relay Provisioning

### 26.1 Directory Layout

```
deploy/terraform/
├── modules/
│   └── nabu-relay/          # cloud-agnostic relay config generator
│       ├── main.tf            #   cloud-init user-data + nabu_config_snippet locals
│       ├── variables.tf       #   relay_name, path_id, listen_port, nabu_secret, …
│       └── outputs.tf         #   user_data, nabu_config_snippet, nabu_endpoint, probe_port
├── oci/                     # OCI ARM64 Ampere A1 (Fransa/Marsilya, path-id 0)
│   ├── main.tf            #   oci provider, VCN, subnet, security list, instance
│   ├── variables.tf
│   └── outputs.tf
└── hetzner/                 # Hetzner Cloud CAX11 ARM64 (Falkenstein, path-id 1)
    ├── main.tf            #   hcloud provider, firewall, ssh_key, server
    ├── variables.tf
    └── outputs.tf
```

### 26.2 nabu-relay Module

The module is **cloud-agnostic** — it generates configuration artifacts only:

| Output | Description |
|--------|-------------|
| `user_data` | cloud-init bootstrap script (install Docker, UFW rules, `docker run`) |
| `nabu_config_snippet` | TOML `[[relays]]` block for the client `nabu.toml` |
| `nabu_endpoint` | `host:port` string passed to `MultiPathConn` |
| `probe_port` | `listen_port + 1000` (UDP echo probe) |

The calling root module (`oci/` or `hetzner/`) creates the cloud instance and
passes `public_ip` back to the module for output interpolation.

### 26.3 OCI Instance (`oci/`)

- **Shape:** `VM.Standard.A1.Flex` — 1 OCPU / 6 GB RAM (Always Free eligible)
- **Region:** `eu-marseille-1` (Fransa / Marsilya)
- **Path ID:** 0, **Listen port:** 7001
- Resources provisioned: VCN, Internet Gateway, Route Table, Security List, Subnet, Instance
- Inbound rules: TCP/22 (SSH), UDP/7001 (relay), UDP/8001 (probe)

### 26.4 Hetzner Instance (`hetzner/`)

- **Type:** `cax11` — 2 vCPU ARM64 / 4 GB RAM (~€4/mo)
- **Location:** `fsn1` (Falkenstein, DE)
- **Path ID:** 1, **Listen port:** 7002
- Resources provisioned: SSH key, Firewall, Server
- Inbound rules: TCP/22 (SSH), UDP/7002 (relay), UDP/8002 (probe)

### 26.5 Security Notes

- All secrets (`nabu_secret`, `hcloud_token`, OCI credentials) are `sensitive = true`.
- **Never** place secrets in `.tf` files. Use `TF_VAR_*` env vars or a Vault-backed backend.
- `user_data` output is marked `sensitive = true` (contains nabu_secret).
- `ignore_changes = [user_data]` prevents re-provisioning on bootstrap script edits.

### 26.6 Usage

```bash
# Hetzner relay
cd deploy/terraform/hetzner
terraform init
export TF_VAR_hcloud_token="$HCLOUD_TOKEN"
export TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"
export TF_VAR_nabu_secret="$NABU_SECRET"
terraform apply

# OCI relay
cd deploy/terraform/oci
terraform init
export TF_VAR_tenancy_ocid="..." TF_VAR_user_ocid="..." \
       TF_VAR_fingerprint="..." TF_VAR_compartment_ocid="..."
export TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"
export TF_VAR_nabu_secret="$NABU_SECRET"
terraform apply
```

After apply, copy `nabu_config_snippet` outputs into the client `nabu.toml` `[[relays]]` section.

---

## Changelog

| Version | Oturum | Changes |
|---------|--------|---------|
| 1.0 | 1.01–1.10 | Core frame format, session lifecycle, encryption (AES-256-GCM), anti-replay |
| 1.1 | 1.11 | TCP transport, HTTPConnect obfuscation layer |
| 1.2 | 1.12 | TLS wrapping with self-signed cert |
| 1.3 | 1.13 | Anti-replay window (ReplayWindow) |
| 1.4 | 1.14 | Rate limiting |
| 1.5 | 1.15 | WebSocket obfuscation layer (§15) |
| 1.6 | 1.16 | §16 Salamander UDP obfuscation |
| 1.7 | 1.17 | §17 Probe Defense (decoy TLS/HTTP response) |
| 1.8 | 1.29 | §18 QUIC/H3 Transport (quic-go v0.59, ALPN nabu/1+h3) |
| 1.9 | 1.30 | §19 JA3/JA4 Fingerprint Normalization (uTLS Chrome133/Firefox120/Edge85/Random profiles) |
| 2.0 | 1.31 | §20 Micro-Phantom Traffic Profile Engine (web_browsing/youtube_sd/instagram_feed CDF profiles, token-bucket shaper, GenerateIdle cover traffic) |
| 2.1 | 1.32 | §21 Governor Adaptive Rate Controller (/proc/net/dev, TimeOfDayCoeff cosine curve, Recommendation channel, non-eBPF Faz-2 version) |
| 2.2 | 1.33 | §22 DPI Statistical Test Framework (KS-test, BucketFrequencyTest, Shannon entropy, 15 unit tests + 7 DPI integration tests) |
| 2.3 | 1.34 | §23 nDPI + Suricata Docker integration tests (ndpiReader v4.2 TLS classification, Suricata 8.0.4 zero-alert assertion, 4 new tests; pure-Go PCAP writer) |
| 2.4 | 1.35 | §24 Multipath QUIC Scheduler (MinRTT+EWMA, BLEST HoL-blocking, Redundant, WeightedRR; 19 unit tests) |
| 2.5 | 1.36 | §25 Relay Network Architecture (MultiPathConn UDP echo probe, relay-network.yml OCI FR + Hetzner DE topology, 13 tests) |
| 2.6 | 1.37 | §26 Terraform Relay Provisioning (nabu-relay module, OCI ARM64 Ampere A1 + Hetzner CAX11 ARM64, cloud-init bootstrap, sensitive secret handling) |
