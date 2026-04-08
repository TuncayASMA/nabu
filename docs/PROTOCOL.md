# NABU Protocol Specification

**Version:** 1.1 (Faz 1 — Architecture Complete)  
**Status:** Reference implementation complete; Faz 2 obfuscation layer pending  
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
11. [Transport Abstraction (Faz 2 Prep)](#transport-abstraction-faz-2-prep)
12. [Security Considerations](#security-considerations)
13. [Changelog](#changelog)

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

## Security Considerations

| Threat                     | Mitigation                                              |
|----------------------------|---------------------------------------------------------|
| Passive traffic analysis   | AES-256-GCM encryption + ephemeral X25519 keys          |
| Replay attacks             | GCM tags are unique per nonce; random 12-byte nonce      |
| PSK brute-force            | Relay drops frames without a matching session silently   |
| SSRF / open-relay abuse    | Private/loopback destinations blocked by default        |
| DoS via packet flood       | Per-source token-bucket rate limiter                    |
| Forward secrecy            | Ephemeral X25519 keys — new key pair per connection      |
| Metadata leakage in errors | Error replies never sent; silent drop policy            |

> **Known limitation (Faz 1):** No anti-replay window beyond GCM nonce
> uniqueness.  A dedicated sequence-number replay window is planned for Faz 2.

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

## Changelog

| Version | Oturum | Changes |
|---------|--------|---------|
| 1.0     | 1.16   | Initial specification: frame format, handshake, encryption, RTT, reliability, rate limiting |
| 1.1     | 1.20   | Added §11 Transport Abstraction (Layer interface, optional capabilities, Faz 2 extension points) |
