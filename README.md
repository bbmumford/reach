# reach

reach lets every node of a peer-to-peer mesh tell the others how to dial it.
Each node runs a `Publisher` that gathers its own reachable addresses from a
set of discoverers (static, DNS, network interfaces, STUN, TURN, UPnP, the
cloud platform's metadata, and addresses peers saw it from), signs them with
its Ed25519 key, and appends the signed `ReachRecord` to a ledger. Peers read
the ledger to learn where to connect; there is no central directory.

How a publisher behaves:

- **Publish only on change.** The address set is fingerprinted (SHA-256 over
  the sorted set, `Digest`); an unchanged set is not published again, and a
  small change is published as a signed delta against the last full record
  (`DeltaRecord`), with a full snapshot every `DeltaThreshold` publishes.
- **Cadence.** Bootstrapping (every 2 seconds for the first 30), churning
  (every 15 seconds) and stable (every 5 minutes, or 15 for the agent
  profile), with full jitter and at most `MaxPublishesPerMin` (default 10).
- **Ordering.** Every record carries a hybrid logical clock stamp and an
  `Epoch` seeded from the clock at start, so a restarted node's records order
  after its earlier ones.
- **Expiry.** Each address has a time to live by source (`DefaultTTLs`); the
  record expires with its longest-lived address. On shutdown the publisher
  writes a tombstone so peers drop it at once.
- **Private addresses.** With a `GroupKey`, private-scope addresses are sealed
  with ChaCha20-Poly1305 (`SealGroup`) so only holders of the key can read them
  (`OpenGroup`).
- **Verified addresses.** A `Prober` asks peers to dial an address back and
  raises the address's confidence when peers in enough regions reach it.
  `ServeVerifyHTTP` answers such requests only for callers its authorize
  function admits (nil admits none), and `DefaultVerifier` dials only a UDP or
  TCP target at a public unicast IP literal.
- **Network changes.** The `events` package reports address and power changes
  (netlink on Linux, PF_ROUTE on macOS, `NotifyUnicastIpAddressChange` on
  Windows, a poller elsewhere, and a captive-portal check), and the publisher
  republishes when they happen.
- **Freshness gossip.** With a `FreshnessBus`, nodes exchange their record
  digests every 30 seconds and pull a record whose digest differs.
- **Last good record.** With a `PersistPath`, the last published record is
  saved and reloaded on the next start.

Receivers check records with `Verify` (and `VerifyDelta`): a record must be
signed, the signature must hold, and the NodeID must be the one aether derives
from the signing key. `NewCacheApplyHook` wraps a ledger cache so it refuses
records that fail those checks, replays and floods (a per-node rate held for a bounded number of NodeIDs, and a
replay window); `SkipSignatureCheck` exists for meshes still carrying unsigned
records and is off by default.

## Use

```sh
go get github.com/bbmumford/reach
```

```go
pub, err := reach.NewPublisher(reach.Config{
	NodeID:    nodeID,      // aether NodeID of signer's public key
	Partition: partition,
	Region:    "syd",
	Signer:    priv,        // ed25519.PrivateKey
	Ledger:    appender,    // anything with Append(ctx, ledger.Record) error
	Provider:  "fly",
	Discoverers: []reach.Discoverer{
		discoverer.NewInterface(41641),
		discoverer.NewSTUN(discoverer.STUNConfig{
			ServerAddrs: []string{"stun.example.com:3478"},
			UDPPort:     41641,
		}),
		discoverer.NewPlatform("fly", 41641),
	},
	PersistPath: filepath.Join(stateDir, "reach.json"),
})
if err != nil {
	return err
}
go pub.Run(ctx)
```

`NotifyAddressChange` and `NotifyRoleChange` make the publisher look again
at once, `ForcePublish` publishes now, and `CurrentAddresses`, `LastDigest`
and `MetadataSnapshot` report what it last published. `Metadata` is a free map
the caller fills (service name, roles, device id) and the record carries signed.

| package | what it holds |
|---|---|
| `reach` | `Publisher`, `Config`, `ReachRecord`, `Address`, `Sign`, `Verify`, deltas, group sealing, the cache hook, the prober, the freshness client |
| `reach/discoverer` | the address sources: `Static`, `DNS`, `Interface`, `STUN`, `TURN` (static, TURN REST and HKDF-HMAC credentials), `UPnP`, `Platform` (Fly, AWS, GCP, Kubernetes, development), `Reflection` |
| `reach/events` | network-change and power events per platform, on one `Bus` |

## Dependencies

- `github.com/ORBTR/aether`: `NewNodeID`, to bind a record's NodeID to its key,
  and its capability flags.
- `github.com/bbmumford/ledger`: the record and ledger types reach writes
  (`Record`, `ReachRecord`, `ReachAddress`) and `ledger/storage`.
- `github.com/bbmumford/ratelimit`: the per-node publish budget
  (`PerNodeRateLimiter`).
- `github.com/pion/stun/v3`, `github.com/pion/turn/v4` and
  `github.com/pion/ice/v3`, for STUN, TURN and ICE candidates.
- `golang.org/x/crypto` (ChaCha20-Poly1305, HKDF) and `golang.org/x/sys`
  (the platform event sources).

## Used by

Importers in the ORBTR estate:

- `github.com/bbmumford/loom/node`: the platform mesh node publishes its
  addresses with reach.
- `github.com/ORBTR/agent/internal/core/wire` (with `discoverer` and
  `events`) and `github.com/ORBTR/agent/systempart`: the device agent.

## Platforms and build

Pure Go, no cgo. `events` has a source per platform selected by build
constraints (`linux`, `darwin`, `windows`, and a poller for every other
system). The module's `go` directive is 1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
