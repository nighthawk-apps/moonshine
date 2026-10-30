# Moonshine Wallet CLI

**Moonshine** is a private, lightweight CLI light wallet for the **DarkFi** blockchain. It connects to **`darkfi-lightwalletd`** over gRPC and syncs with **UnifOMR only** (scheme `0x05`). There is no PerfOMR fallback.

**3.00.026** (crate semver **3.0.26** — leading zeros are not valid Cargo versions): Speaks lightwalletd proto 2.0.0 (lightwalletd **0.3.0** or later). Sync installs a snapshot checkpoint, resumes the Money tree from its saved height, sends only padded commitment and nullifier ranges, reuses one pooled UnifOMR detection key, and retries PIR before fetching the padded window. Tor is Arti 0.47. A send spends one coin, the largest that covers the amount plus fee. DarkFi rejects a two-input transfer proof, so a pile of smaller coins is not combined. DarkFi checkout `8af61b3f0` (`nighthawk-testnet`, path dependency). Reorg recovery unspends a coin only when its nullifier was in a block above the fork. New wallets take `MOONSHINE_WALLET_PASS` and keep the wrap key inside the encrypted database. Sends attach a UniFOMR clue for the sender's change outputs. Money Merkle tree is backfilled from genesis after a birthday rescan so spend proofs stay on-chain (Money `Custom(5)` / `TransferMerkleRootNotFound`). CI checks out the pinned `nighthawk24/darkfi` sibling as `darkfi-nighthawk-testnet`. FIFO-capped clue-registration session cache (10,000 ids; updates do not refresh eviction order). Reorg recovery reports real SQLite `execute` rowcounts for notes and transactions (`invalidate_above_height`). Instant Sync + UnifOMR-strict receive (`sync --force-trial` / `--allow-trial` for trial-decrypt fallback). Testnet explorer: [https://explorer.testnet.dark.fi](https://explorer.testnet.dark.fi).

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
| **Sibling `darkfi-nighthawk-testnet`** | Directory name is literal. Pin `8af61b3f0` (full `8af61b3f03b47164b4e4e01fcdc84e2744cb8570`, nighthawk24 `nighthawk-testnet`). A `darkfi` checkout on master is **not** enough, and `git.dark.fi` returns HTTP 504 and does not have this pin. You may `ln -s nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet` — that tree is the same pin. |
| **Sibling `darkfi-lightwalletd`** | Proto from `../darkfi-lightwalletd/proto/lightwallet.proto` |
| **Running lightwalletd** | Local or remote before `moonshine sync` |

Clone the path dependencies as **sibling directories** (names matter — see `Cargo.toml` / `build.rs`):

```text
parent/
  darkfi-nighthawk-testnet/ # MUST be this name — pin 8af61b3f0, not git.dark.fi master
  darkfi-lightwalletd/      # gRPC server + proto + UnifOMR crate
  moonshine/                # this repo
  # optional; same pin if you already built Android:
  nighthawk-android-wallet/third_party/darkfi
```

Reuse the Android vendored tree (same pin) instead of a second clone:

```bash
# from the parent/ directory that contains moonshine/
ln -sfn nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet
# Cargo git deps inside that tree (git.dark.fi returns HTTP 504):
#   kvdb-overlay  https://gitlab.com/nighthawk24/kvdb-overlay  accd2689
#   RandomX       https://codeberg.org/darkrenaissance/RandomX 0e31d5a
#   rust-url      https://github.com/darkrenaissance/rust-url  branch v258
```

Pin DarkFi to the same revision lightwalletd uses (reproducible builds):

```bash
# from darkfi-lightwalletd/
FORCE_DARKFI_PIN=1 ./scripts/fetch-darkfi.sh
# See docs/darkfi-pin.md — current SHA 8af61b3f03b47164b4e4e01fcdc84e2744cb8570
```

Moonshine’s own pruned wallet remains **SQLCipher** (`PRAGMA key`) by design — it does
**not** use upstream `bin/drk` / turso. Mobile/desktop UniFFI clients track tip `drk`.

```bash
brew install protobuf   # or: sudo apt install protobuf-compiler
```

`Cargo.lock` is committed so release builds stay reproducible.

---

## Build

From the `moonshine/` directory (with `../darkfi-nighthawk-testnet` and `../darkfi-lightwalletd` present):

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
use_tor = false
```

```bash
# Local LWD (Tor auto-skipped for loopback):
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
| **Clue PK register on sync** | ✅ | Fail-closed if registration fails for all addresses. Session cache is FIFO-capped at 10,000 ids |
| **UnifOMR send clue** | ✅ | `GetCluePublicKey` → `build_omr_clue_from_pk`; abort if unavailable. `tx send --no-omr` omits the clue for trial-decrypt receive. Change outputs get `extra_omr_clues`, but strict sync still does not make that change spendable. Run `sync --force-trial` after the change is in a block |
| **One input per send** | ✅ | Largest coin that covers amount + fee. A two-input proof is not built; darkfid rejects it |
| **Localnet UnifOMR (2026-10-21)** | ✅ | 100/100 each way with Android and with desktop. `--no-omr` payments were received by those wallets under trial decrypt |
| **Payment memo on wire** | ✅ | `--memo` → OMR-aware bytes in recipient `MoneyNote::memo` (not local-only) |
| **Multi detection_keys** | ✅ | Up to 16 wallet secrets in `GetUnifOmrDigest` |
| **Local BlockCache** | ✅ | Sparse/PIR compact blocks cached beside wallet DB |
| **Instant Sync Checkpoints** | ✅ | Fast Merkle tree restore from authenticated `CheckpointSnapshot` (see [docs/instant-sync-strategy.md](docs/instant-sync-strategy.md)) |
| **Proto Version Lockstep** | ✅ | Validates `LightInfo.proto_version` (1.x.x) on connect |
| **OMR Err → no silent trial (S15)** | ✅ | Tip not advanced on OMR **error** |
| **Empty OMR → supplemental trial** | ❌ (strict) | Use `sync --force-trial` for miss-safety |
| **Tip regression rewind** | ✅ | Rewinds sync height when tip < last synced. Deleted note/tx counts come from SQLite `execute` rowcounts, not log-line length |
| **`chain_name` network guard** | ✅ | Must match config `network` |
| **TLS pin remote HTTPS** | ✅ | `tls_pin_sha256` + `PinnedVerifier` (leaf DER SHA-256); remote cleartext refused |
| **Address validation** | ✅ | DarkFi checksum addresses |
| **Network-aware addresses** | ✅ | Create/import use config network |

### Encryption & at-rest

| Feature | Status | Notes |
|---------|--------|-------|
| **SQLCipher DB (S14)** | ✅ | `PRAGMA key` from `MOONSHINE_WALLET_PASS` or `{db}.pass` (0600) |
| **Secret wrap** | ✅ | Address `secret_key` BLOBs wrapped (`MSK1` + MAC). The wrap key is stored inside the encrypted database. A legacy `.wrapkey` file is imported once and deleted |
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
- Empty OMR → **no** supplemental trial (strict UnifOMR); use `sync --force-trial` for miss-safety
- Send fails closed unless GetClue **ownership proof** verifies (rejects directory decoys)
- First-run default LWD: loopback `http://127.0.0.1:9067` (Tor off). Remote HTTPS still needs `tls_pin_sha256` + Tor if you want it.
- Limits: [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md) (Param2 active)
- MVP fork archive: [`docs/unifomr_mvp_archive.md`](docs/unifomr_mvp_archive.md)
- Checklist: [`docs/verification-checklist.md`](docs/verification-checklist.md)

## Known issues

1. **One input per transaction.** darkfid rejected a two-input transfer proof on the 2026-10-21 localnet. Selection spends a single coin that covers the amount plus the 0.05 DRK fee. It does not combine smaller coins. If no such coin is visible yet, the send stops before broadcast.
2. **Own change needs `sync --force-trial`.** The recipient clue does not cover the sender's change. `extra_omr_clues` are attached, and strict sync still did not make that change spendable on the localnet. Sync with `--force-trial` after the change is in a block before the next send. Until then, selection can see only the small coins and report that none covers the fee.
3. **`--no-omr` is invisible to strict sync.** Android and desktop received those payments only with trial decrypt forced. Moonshine will not see a clue-less incoming payment on a normal sync.
4. **`git.dark.fi` returns HTTP 504** and does not publish pin `8af61b3f0`. Clone `nighthawk24/darkfi` (or symlink the Android `third_party/darkfi`). `kvdb-overlay`, RandomX, and `rust-url` are fetched from GitLab, Codeberg, and GitHub.

---

## Related projects

| Sibling directory | Role |
|-------------------|------|
| `../darkfi-nighthawk-testnet` | DarkFi SDK pin `8af61b3f0` (symlink to `nighthawk-android-wallet/third_party/darkfi`) |
| `../darkfi-lightwalletd` | gRPC lightwalletd + shared UnifOMR |
| `../darkfi-mobile-ffi` | Shared UniFFI crate (Android / iOS / desktop) |
| `../nighthawk-android-wallet` | Android wallet (`third_party/darkfi` = same pin) |
| `../nighthawk-ios-wallet` | iOS wallet |
| `../nighthawk-app-desktop` | Desktop wallet (Tauri) |

---

## License

AGPL-3.0-only (see source headers).
