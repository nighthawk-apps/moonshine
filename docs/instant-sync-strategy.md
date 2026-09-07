# Instant Sync Strategy — Moonshine

> **Last updated**: 2026-09-07
>
> This document describes the instant sync changes planned across all Nighthawk
> platforms. Moonshine has its **own** Rust sync engine (`src/sync.rs`,
> `src/client.rs`) and requires **parallel porting** of each feature.

## Philosophy

Port DarkFi contracts + wire formats. Keep LWD. Do **not** port the official
GUI or its `darkfid` JSON-RPC scanner. Official `scan_blocks` into Nighthawk
would be a regression.

## Platform Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    darkfi-mobile-ffi (Rust)                        │
│  proto/lightwallet.proto · sync.rs · lightwallet_client.rs         │
│  omr.rs · unifomr.rs · bootstrap.rs · birthday.rs                 │
│  NEW: checkpoint.rs · sync_pipeline.rs · zkas_cache.rs             │
├────────────┬────────────┬──────────────┬──────────────────────────┤
│  Android   │    iOS     │   Desktop    │      Moonshine           │
│  UniFFI    │  UniFFI    │  Cargo dep   │  Own sync.rs/client.rs   │
│  (Kotlin)  │  (Swift)   │  (Tauri)     │  (standalone Rust CLI)   │
└────────────┴────────────┴──────────────┴──────────────────────────┘
```

## Moonshine-Specific Porting

Unlike Android/iOS/Desktop which share the `darkfi-mobile-ffi` crate,
Moonshine must port each feature into its own codebase.

### Step 0: Proto Sync (PREREQUISITE)

Moonshine's proto is behind mobile's. Must be updated first.

| Feature | Current Moonshine | Target (match mobile) |
|---------|-------------------|-----------------------|
| `GetUnifOmrDigest` | `OmrDigestRequest` (single msg) | `stream DetectionKeyChunk` (1 MiB chunks) |
| `CompactOutput.omr_metadata_enc` | Missing | Add field 6 |
| `RawTransaction.omr_metadata_enc` | Missing | Add field 4 |
| `OmrClueRegistration.omr_metadata_enc` | Missing | Add field 4 |
| `LightInfo.directory_attest_pubkey` | Missing | Add field 9 |
| `LightInfo.proto_version` | Missing | Add field 10 |
| `TreeState` auth fields | Missing | Add fields 3–5 |
| `CheckpointSnapshot` message | Missing | Add new message + RPC |

### Changes Per Feature

| # | Change | Moonshine Files | Notes |
|---|--------|-----------------|-------|
| 1a | Historical GetTreeState | `src/client.rs`, `src/sync.rs` | Already calls `get_tree_state(tip)` at L476; extend to historical + auth |
| 1b | Concurrent gRPC | `src/sync.rs` | Add `tokio::join!` for commitments + nullifiers |
| 1c | Checkpoint snapshots | `src/client.rs`, `src/sync.rs` | Add checkpoint download + apply in bootstrap |
| 1d | OMR/PIR metering | `src/client.rs` | Add `RpcMetrics` + rate limiting |
| 2a | Birthday enforcement | `src/sync.rs` | ✅ **Already enforced** at L170: `scan_start = (last_synced + 1).max(birthday)` |
| 2b | Pipeline prefetch | `src/sync.rs` | Inline pipeline (no separate module needed) |
| 2c | OMR-first audit | `src/sync.rs` | Already OMR-first; add logging |
| 2d | ZkAS cache | NEW `src/zkas_cache.rs`, `src/tx_builder.rs` | SQLite-backed cache |
| 2e | Proto lockstep | `src/client.rs` | Parse `proto_version`, CLI warning |

## Execution Order

1. **Proto sync** — update proto to match mobile (prerequisite for all else)
2. **1b** Concurrent gRPC (`tokio::join!` for commitments + nullifiers)
3. **2b** Pipeline OMR prefetch
4. **1a** Historical GetTreeState with authentication
5. **1c** Checkpoint snapshots for instant restore
6. **2d** ZkAS / proving key cache
7. **1d** OMR/PIR metering
8. **2e** Proto version lockstep
9. **2c** OMR-first audit (logging)

> Note: 2a (birthday enforcement) is already implemented in Moonshine.

## `scan_blocks` Rejection

Moonshine uses its own `src/sync.rs` talking to LWD only. It does not import
or call `drk::rpc::scan_blocks`. The sync engine connects exclusively to
`darkfi-lightwalletd` gRPC — never directly to `darkfid`.

## See Also

- [docs/darkfi-pin.md](darkfi-pin.md) — TLS certificate pinning
- [docs/verification-checklist.md](verification-checklist.md) — verification checklist
