# NABU Protocol Specification

**Version:** 1.4 (Faz 2 — Anti-replay Window + Client TLS Dialer)  
**Status:** Reference implementation complete; Faz 2 obfuscation + TLS + Anti-replay operational  
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
16. [Changelog](#changelog)

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
