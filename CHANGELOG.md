# Changelog

## [0.1.0](https://github.com/bbmumford/reach/compare/v0.0.14...v0.1.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* ServeVerifyHTTP takes a fourth argument, the authorize function.
* CacheHookConfig.RequireValidSig is removed. A hook verifies by default; set SkipSignatureCheck to apply records that fail verification.
* key the record on its partition and seal private addresses to a group
* JSON field names of the reach records are lowerCamelCase

### Features

* discovery finds candidate dial addresses for mesh peers ([3298a0d](https://github.com/bbmumford/reach/commit/3298a0d48528690796f83fee272dc95a95623d43))


### Bug Fixes

* a NodeID flood leaves a tracked node's budget in place, and PerNodeRateLimiter refuses an untracked NodeID while its map is full ([d76ef45](https://github.com/bbmumford/reach/commit/d76ef45b5825763122bc3b3beae1be77f17e8c39))
* CacheApplyHook's replay guard keeps per-node state for the ReplayWindow its config states ([2f4e836](https://github.com/bbmumford/reach/commit/2f4e836a852a57337eb5c7dad971ec7aa3c5d264))
* Clock stamps records from swarm's HLC, so a remote stamp far ahead no longer drags this node's records ahead of real time ([fa981a3](https://github.com/bbmumford/reach/commit/fa981a3b3d84e6eca86330f997b2636531a085b3))
* go.mod requires aether v0.0.118, ledger v0.1.0, ratelimit v0.1.0, swarm v0.2.0 and whisper v0.0.20, and Go 1.27.4 ([2a85429](https://github.com/bbmumford/reach/commit/2a854297a8f49b314700a8a53210bd32a344555b))
* ICE candidate lines are built with pion/ice/v4, and pion/stun/v3 is raised to v3.1.5 ([77b1a4f](https://github.com/bbmumford/reach/commit/77b1a4fba68e30408b31a1f418851f1162c152ce))
* LadCacheDeltaApplier applies a delta only when the base's own node signed it ([c17b5f2](https://github.com/bbmumford/reach/commit/c17b5f263a5f53542d5b0b72715798c8df483cc5))
* OpenGroup refuses a section whose nonce is not the cipher's length ([9670c09](https://github.com/bbmumford/reach/commit/9670c09982483978529105f4ce0a89a627ca1583))
* PerNodeRateLimiter holds a budget for a bounded number of NodeIDs ([a21f829](https://github.com/bbmumford/reach/commit/a21f82930e3454da1965c32dd5223dafc59535dd))
* publish the record partition under the key ledger reads ([716dc54](https://github.com/bbmumford/reach/commit/716dc543fe596bb53bb2f06551cf3853d00847c2))
* the cache hook verifies a record before charging it and charges rate and replay state to the NodeID the record's key proves, so a forged record can neither spend nor advance another node's budget ([94491ae](https://github.com/bbmumford/reach/commit/94491aef1eadcccb847bb7e7aad956e3eb8760a5))
* the cache hook verifies every record unless SkipSignatureCheck is set, replacing RequireValidSig, whose zero value skipped every check ([91a6fa0](https://github.com/bbmumford/reach/commit/91a6fa00ccecd23ae975ccb21fc3d47a11ce4f6f))
* the CacheApplyHook ledger forwards StreamWithEnd, so a consumer handed the wrapper reads why its stream ended ([a05ddef](https://github.com/bbmumford/reach/commit/a05ddef0bbbd843e11254a636f9c7b0b8b64d6b2))
* the prober stops collecting when its window ends, and dropped close and registration errors say why ([a0a2bea](https://github.com/bbmumford/reach/commit/a0a2bea2251309b1fdb0f812ec2771865fd1d356))
* the verify handler serves only an authorized caller, and DefaultVerifier dials only a public address ([65c3778](https://github.com/bbmumford/reach/commit/65c37784b3eef320541f8d939ece0f5cb9758fc9))
* Verify and VerifyDelta refuse a record whose NodeID is not the NodeID its signing key derives, so a record speaks only for the node whose key signed it ([be7c0d1](https://github.com/bbmumford/reach/commit/be7c0d181124a15bff7bd599e608f7c0e1a890eb))


### Code Refactoring

* JSON field names of the reach records are lowerCamelCase ([2db2a8b](https://github.com/bbmumford/reach/commit/2db2a8be0f538f93870ef2b211cd136cdcc51d45))
* key the record on its partition and seal private addresses to a group ([bf4c7c9](https://github.com/bbmumford/reach/commit/bf4c7c94b1e0e46ab760a702eb6c2c8ce7e7e4f9))
