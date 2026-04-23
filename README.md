# Reach — Self-Reach Publisher for Peer Meshes

```
go get github.com/bbmumford/reach
```

**Related:** [Ledger](https://github.com/bbmumford/ledger) (record store + gossip cache) · [Whisper](https://github.com/bbmumford/whisper) (gossip engine) · [Aether](https://github.com/ORBTR/Aether) (wire protocol)

> **Reach** is a self-reachability publisher for peer-to-peer meshes. Each node runs a `Publisher` that discovers its own addresses (DNS, STUN, TURN, cloud metadata, interface enumeration, peer reflection), signs the result with Ed25519, and writes it to the distributed ledger. Peers learn how to dial each other without any central directory. Paired with Whisper gossip, a freshness digest propagates mesh-wide so every peer converges within seconds of an address change.

## Core capabilities

- **Fingerprint-and-skip** — canonical SHA-256 over the sorted address set; re-publishes only when the address set actually changes.
- **Adaptive cadence** — STABLE (5 min) / CHURNING (15 s) / BOOTSTRAPPING (2 s) with full-jitter + leaky-bucket cap.
- **Hybrid Logical Clock** — monotonic ordering that survives wall-clock skew; `Epoch` bumps on restart.
- **Ed25519 signed** — receivers verify authenticity before applying.
- **Per-address TTL** — DNS 1h, STUN 2min, reflective 10min, static ∞; record TTL = max of per-address TTLs.
- **Platform-aware discovery** — Fly (`FLY_PUBLIC_IP`), AWS (IMDSv2), GCP (metadata.google.internal), Kubernetes (downward API), dev (STUN + interface enum).
- **STUN + TURN** — `pion/stun/v3` against a fleet STUN, `pion/turn/v4` relay allocation with HKDF-derived per-tenant credentials.
- **ICE candidates** — host/srflx/relay candidates emitted alongside the flat address list (RFC 8445).
- **Confidence scoring** — peer-echo probes mark verified addresses with `Confidence >= 60`, unverified with `< 20`.
- **Freshness gossip** — `reach.freshness` whisper topic broadcasts a digest every 30 s; mismatch triggers a pull.
- **Event-driven** — netlink (linux), PF_ROUTE (darwin), NotifyUnicastIpAddressChange (windows), plus suspend/resume hooks.
- **Graceful tombstones** — on shutdown the node publishes an empty record with `Tombstone`; peers expunge immediately.
- **Per-org encryption** — ChaCha20-Poly1305 AEAD seals private-scope addresses (e.g. Fly `fdaa:`) from non-org peers.
- **Rate limit + replay guard** — per-NodeID publish cap; strictly-increasing HLC per Epoch.
- **Last-good persistence** — `~/.hstles/reach.json` speeds cold-start reach publication.

## Quick start

```go
import (
    "github.com/bbmumford/reach"
    "github.com/bbmumford/reach/discoverer"
)

pub, err := reach.NewPublisher(reach.Config{
    NodeID:   myNodeID,
    Region:   "iad",
    TenantID: myTenantID,
    Signer:   edPrivateKey,
    Ledger:   ledgerAppender,          // any ledger.Ledger impl
    Whisper:  freshnessBus,             // optional — enables reach.freshness gossip
    Provider: "fly",                    // platform detection hint
    Discoverers: []reach.Discoverer{
        discoverer.NewStatic(staticAddrs),
        discoverer.NewDNS("node.example.com", 41641),
        discoverer.NewInterface(41641),
        discoverer.NewSTUN(discoverer.STUNConfig{
            ServerAddrs: []string{"stun.example.com:3478"},
            UDPPort:     41641,
            // AuthFunc: discoverer.StaticSTUNAuth("user","realm","pw"), // optional — RFC 5389 long-term cred
        }),
        discoverer.NewTURN(discoverer.TURNConfig{
            ServerAddr: "turn.example.com:3478",
            // Pick one credential scheme:
            // 1. Static long-term: Username + Password
            // 2. Standard TURN REST: StandardRESTCredentials(userID, sharedSecret, ttl)
            // 3. Custom: any CredentialFunc you supply
            CredentialFunc: discoverer.StandardRESTCredentials(myUserID, sharedSecret, 15*time.Minute),
        }),
        discoverer.NewPlatform("fly", 41641),
    },
})
if err != nil { return err }
go pub.Run(ctx)
```

The publisher runs its own scheduler, reacts to platform events, and publishes to the ledger — no operator intervention required. Everything is configuration-driven; the package has no baked-in server addresses or tenant IDs.

## Package layout

- `reach` — public API (`Publisher`, `Config`, `ReachRecord` extensions)
- `reach/discoverer` — pluggable address sources
- `reach/events` — platform event hooks (netlink / PF_ROUTE / win32)
- `reach/internal` — shared test harness

Consumers that only read records import `github.com/bbmumford/ledger` directly — this package is publisher-only and pulls in `pion/stun`, `pion/turn`, `pion/ice` for discovery.

## License

MIT — see [LICENSE](LICENSE).
