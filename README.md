# Moonshine Wallet CLI

**Moonshine** is a private, lightweight CLI light wallet for the **DarkFi** blockchain. It connects to **`darkfi-lightwalletd`** over gRPC and syncs with **UnifOMR only** (scheme `0x05`). There is no PerfOMR fallback.

> **Strict UnifOMR (hard-coded):** Moonshine does **not** run supplemental / gap trial decrypt. **Only** transactions that carry UnifOMR clues are discovered during normal sync — typically **Moonshine ↔ Moonshine**, or **Nighthawk → Moonshine**. Payments from upstream `drk` / other non-UnifOMR wallets will **not** appear unless you explicitly run `moonshine sync --force-trial` (privacy trade-off). Nighthawk Android / iOS / desktop default the opposite (trial-decrypt fallback on) so they can receive from any DarkFi wallet.

Unlike full nodes (`darkfid`) or the heavy CLI wallet (`drk`), Moonshine keeps a **pruned SQLite** wallet (SQLCipher + wrapped secrets) and a small on-disk footprint.

## Contents

- [Prerequisites](#prerequisites)
- [Build](#build)
- [Configuration](#configuration)
- [Quick start](#quick-start)
- [CLI command tree](#cli-command-tree)
- [Features](#features)
- [Related projects](#related-projects)
- [License](#license)

---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Rust** stable | [rustup](https://rustup.rs/) |
| **`protoc`** | On `PATH` |
| **Sibling `darkfi`** | `../darkfi` at the SHA in `../darkfi-lightwalletd/scripts/darkfi.rev` |
| **Sibling `darkfi-lightwalletd`** | Proto from `../darkfi-lightwalletd/proto/lightwallet.proto` |
| **Running lightwalletd** | Local or remote before `moonshine sync` |

Clone the path dependencies as **sibling directories** (names matter — see `Cargo.toml` / `build.rs`):

```text
parent/
  darkfi/                 # upstream DarkFi (https://github.com/darkrenaissance/darkfi)
  darkfi-lightwalletd/    # gRPC server + proto + UnifOMR crate
  moonshine/              # this repo
  # optional client siblings (not required to build moonshine):
  darkfi-mobile-ffi/      # shared UniFFI crate used by mobile/desktop
  nighthawk-android-wallet/
  nighthawk-ios-wallet/
  nighthawk-desktop/
```

Pin DarkFi to the same revision lightwalletd uses (reproducible builds):

```bash
# from darkfi-lightwalletd/
FORCE_DARKFI_PIN=1 ./scripts/fetch-darkfi.sh
```

Moonshine’s own pruned wallet remains **SQLCipher** (`PRAGMA key`) by design — it does
**not** use upstream `bin/drk` / turso. Mobile/desktop UniFFI clients track tip `drk`.

```bash
brew install protobuf   # or: sudo apt install protobuf-compiler
```

`Cargo.lock` is committed so release builds stay reproducible.

---

## Build

From the `moonshine/` directory (with `../darkfi` and `../darkfi-lightwalletd` present):

```bash
cargo build --release
# Binary: ./target/release/moonshine

cargo test
```

---

## Configuration

`~/.config/moonshine/config.toml` (created on first run):

```toml
server_url = "http://127.0.0.1:9067"
network = "testnet"
```

```bash
moonshine --server http://127.0.0.1:9067 sync
```

Optional wallet passphrase for SQLCipher (otherwise a random `{wallet}.pass` file is created):

```bash
export MOONSHINE_WALLET_PASS='your-strong-passphrase'
```

`network` must match lightwalletd (`mainnet` / `testnet`).

### Remote HTTPS / TLS pin

Remote cleartext (`http://` to non-loopback) is **refused**. For remote servers use `https://` and set `tls_pin_sha256` in config:

```toml
server_url = "https://lwd.example.com:9067"
tls_pin_sha256 = "<64 hex chars>"   # SHA-256 of the *leaf* certificate DER
```

Moonshine’s `PinnedVerifier` checks that hash against the presented leaf cert (same policy as mobile). Localhost / `127.0.0.1` / `[::1]` may use cleartext without a pin. See [`../darkfi-lightwalletd/docs/TLS_PINNING.md`](../darkfi-lightwalletd/docs/TLS_PINNING.md).

---

## Quick start

```bash
# Terminal A — darkfid (testnet example)
# Terminal B — lightwalletd (see darkfi-lightwalletd README; bind 127.0.0.1 or TLS)

moonshine wallet create --name main
moonshine address default
moonshine sync
moonshine balance
moonshine tx send --to <address> --amount 1.5 --token DRK
# or: moonshine tx broadcast <hex>   # requires parseable recipient for UnifOMR clue
```

---

## CLI command tree

```text
moonshine
├── wallet create | import | export | delete | list | info
├── address list | new | default
├── balance
├── coins list
├── tx send | list | show | broadcast
├── sync [--force-trial]
├── rescan
├── status
├── config show | set
├── doctor
├── prune
└── version
```

---

## Features

### Sync & OMR

| Feature | Status | Notes |
|---------|--------|-------|
| **UnifOMR only (0x05)** | ✅ | `GetUnifOmrDigest` + `FetchPirBatch` when capabilities say `unifomr` |
| **Clue PK register on sync** | ✅ | Fail-closed if registration fails for all addresses |
| **UnifOMR send clue** | ✅ | `GetCluePublicKey` → `build_omr_clue_from_pk`; abort if unavailable |
| **Payment memo on wire** | ✅ | `--memo` → OMR-aware bytes in recipient `MoneyNote::memo` (not local-only) |
| **Multi detection_keys** | ✅ | Up to 16 wallet secrets in `GetUnifOmrDigest` |
| **Local BlockCache** | ✅ | Sparse/PIR compact blocks cached beside wallet DB |
| **OMR Err → no silent trial (S15)** | ✅ | Tip not advanced on OMR **error** |
| **Empty OMR → supplemental trial** | ✅ | Privacy-degrading miss-safety (documented) |
| **Tip regression rewind** | ✅ | Rewinds sync height when tip < last synced |
| **`chain_name` network guard** | ✅ | Must match config `network` |
| **TLS pin remote HTTPS** | ✅ | `tls_pin_sha256` + `PinnedVerifier` (leaf DER SHA-256); remote cleartext refused |
| **Address validation** | ✅ | DarkFi checksum addresses |
| **Network-aware addresses** | ✅ | Create/import use config network |

### Encryption & at-rest

| Feature | Status | Notes |
|---------|--------|-------|
| **SQLCipher DB (S14)** | ✅ | `PRAGMA key` from `MOONSHINE_WALLET_PASS` or `{db}.pass` (0600) |
| **Secret wrap** | ✅ | Address `secret_key` BLOBs wrapped (`MSK1` + MAC); `.wrapkey` sidecar |
| **WAL + secure_delete** | ✅ | SQLite pragmas on open |
| **22-word DarkFi mnemonic** | ✅ | Same derivation as Nighthawk Android/iOS |

### Failsafes

| Feature | Status | Notes |
|---------|--------|-------|
| **Log / error redaction** | ✅ | Endpoints stripped from sync errors |
| **Broadcast without clue refused** | ✅ | `tx broadcast` requires parseable recipient for UnifOMR |
| **Capabilities probe** | ✅ | Skip digest if server reports OMR disabled / non-UnifOMR |

### UnifOMR (scheme 0x05)

- Requires **darkfi-lightwalletd** with `fhe-omr`
- Cross-client crypto parity: RLWE `n=1024`, signed AHE, `CLUE_ERROR_BOUND=2`, length-prefixed SealPIR limbs
- Flow: RegisterCluePublicKey → GetClue → SendTransaction(omr_clue) → GetUnifOmrDigest → FetchPirBatch
- Empty OMR → supplemental trial decrypt (decoy directory ≠ unregistered failure)
- Default local: `http://127.0.0.1:9067`
- Limits: [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md) (Param2 active)
- MVP fork archive: [`docs/unifomr_mvp_archive.md`](docs/unifomr_mvp_archive.md)
- Checklist: [`docs/verification-checklist.md`](docs/verification-checklist.md)

---

## Related projects

| Sibling directory | Role |
|-------------------|------|
| `../darkfi` | DarkFi node / SDK |
| `../darkfi-lightwalletd` | gRPC lightwalletd + shared UnifOMR |
| `../darkfi-mobile-ffi` | Shared UniFFI crate (Android / iOS / desktop) |
| `../nighthawk-android-wallet` | Android wallet |
| `../nighthawk-ios-wallet` | iOS wallet |
| `../nighthawk-desktop` | Desktop wallet (Tauri) |

---

## License

AGPL-3.0-only (see source headers).
