# Moonshine Wallet CLI

**Moonshine 3.2.1** is a private, lightweight CLI light wallet for the **DarkFi** blockchain. It connects to **`darkfi-lightwalletd`** over gRPC using the standalone MIT [`blackhawk-unifomr`](https://github.com/nighthawk-apps/blackhawk) crate (`0.3.0`). The default sync is padded trial decryption. Experimental UnifOMR is off unless you pass `--unifomr` or set `experimental_unifomr = true`. Fee selection follows the shuffled change output. DarkFi pin `b87318e80`. Same release as Android 3.2.01 and desktop 3.2.1 (iOS 3.01.24 pending 3.2.01). Aligns with lightwalletd 0.3.15.

> **Trial decryption is the default.** Payments from `drk`, Nighthawk, and Moonshine are found from the note itself. `--force-trial` still forces a full pass. `--unifomr` registers clue keys and can miss funds when the other wallet is not registered on this same lightwalletd.

Unlike full nodes (`darkfid`) or the heavy CLI wallet (`drk`), Moonshine keeps a **pruned SQLite** wallet (SQLCipher + wrapped secrets) and a small on-disk footprint.

## Executive Summary: Why Nighthawk Leads in Privacy

Nighthawk is engineered as a full-stack private money and communications suite with zero transparent escape hatches:

- **Shielded-only ZK base layer (DarkFi Halo2):** Every transfer, custom token mint/send, and DAO governance action is shielded inside Halo2 zero-knowledge proofs against the global Merkle tree. Unlike Zcash, there are no transparent `t-addr` pools, no multi-pool value splits, and no TEX-style forced deshielding; unlike Monero (pre-FCMP++), anonymity sets are not limited to finite decoy ring signatures; unlike Namada/Penumbra/Pirate Chain, full-stack privacy spans CLI, mobile, desktop, and integrated P2P chat.
- **Network-layer privacy on by default:** Moonshine defaults to **Tor** with fail-closed leaf TLS certificate pinning and strict refusal of non-loopback cleartext HTTP, while Android and iOS default to the **Nym mixnet** (with atomic embedded Arti Tor switching and persistent Direct-disable locks).
- **Private light-client sync:** Padded trial decryption runs by default over Tor; opt-in **UnifOMR (Param2, ePrint 2026/910) + batch PIR** uses power-of-2 padded digest windows, decoy clue directories with ≥250 ms timing padding, and fail-closed full-window streaming on PIR failures.
- **Hardened local secrets:** Moonshine enforces Argon2id passphrase stretching (`pass_kdf`), OS-CSPRNG per-wallet wrap keys, `XChaCha20-Poly1305` secret wrapping at rest in SQLCipher, and `0600` atomic key-file handling.

## Contents

- [Prerequisites](#prerequisites)
- [Build](#build)
- [Configuration](#configuration)
- [Quick start](#quick-start)
- [CLI command tree](#cli-command-tree)
- [Features](#features)
- [Related projects](#related-projects)
- [License](#license)
- [Create a token and a DAO](docs/deploy-a-dao.md)

---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Rust** stable | [rustup](https://rustup.rs/) |
| **`protoc`** | On `PATH` |
| **Sibling `darkfi-nighthawk-testnet`** | Directory name is literal. Pin `b87318e80` (full `b87318e80968ea071fbd3a56eb1ea17110252753`, nighthawk24 `nighthawk-testnet`). A `darkfi` checkout on master is **not** enough, and `git.dark.fi` returns HTTP 504 and does not have this pin. |
| **Sibling `darkfi-lightwalletd`** | Shared `darkfi-lightwalletd` crate for UnifOMR (`build.rs` compiles local `proto/lightwallet.proto`, kept lockstep with `../darkfi-lightwalletd/proto/lightwallet.proto`) |
| **Running lightwalletd** | Local or remote before `moonshine sync` |

Clone the path dependencies as **sibling directories** (names matter — see `Cargo.toml` / `build.rs`):

```text
parent/
  darkfi-nighthawk-testnet/ # MUST be this name — pin b87318e80, not git.dark.fi master
  darkfi-lightwalletd/      # gRPC server + proto + UnifOMR crate
  moonshine/                # this repo
  # optional; same pin if you already built Android:
  nighthawk-android-wallet/third_party/darkfi
```

Reuse the Android vendored tree (same pin) instead of a second clone:

```bash
# Clean setup on a new Mac:
brew install protobuf

# Sibling darkfi checkout at required pin (b87318e80):
git -C ../darkfi worktree add --detach ../darkfi-nighthawk-testnet origin/nighthawk-testnet
# Or reuse the Android pin:
# ln -sfn nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet
```

Pin DarkFi to the same revision lightwalletd uses (reproducible builds):

```bash
# from darkfi-lightwalletd/
FORCE_DARKFI_PIN=1 ./scripts/fetch-darkfi.sh
# See docs/darkfi-pin.md — current SHA b87318e80968ea071fbd3a56eb1ea17110252753
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

`~/.config/moonshine/config.toml` (created on first run; default testnet lightwalletd is Mac Studio ngrok TLS with Tor enabled):

```toml
server_url = "https://epidermis-sandbox-marshland.ngrok-free.dev"
network = "testnet"
tls_pin_sha256 = "d8163009e3bb0bac39adbbfeb227827a91a590b96ec33f72576278c492be628e"
use_tor = true
```

`moonshine tx send` and `moonshine tx broadcast` report **Broadcasted** only after confirming the transaction landed in lightwalletd's mempool via `GetTransaction`.

```bash
# Local LWD (Tor auto-skipped for loopback):
moonshine --server http://127.0.0.1:9067 sync
```

Required wallet passphrase for SQLCipher on new wallets (not written beside the DB; legacy wallets that already have a `{wallet}.pass` file still open):

```bash
export MOONSHINE_WALLET_PASS='your-strong-passphrase'
```

`network` must match lightwalletd (`mainnet` / `testnet` / `localnet`). Localnet payment addresses use the Mainnet `D…` prefix (same as `drk`).

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

moonshine wallet create main
moonshine address default
moonshine sync
moonshine balance
moonshine tx list
moonshine tx send --to <address> --amount 1.5 --token DRK
# or send custom tokens or fund a DAO treasury with spend-hook & user-data:
# moonshine tx send --to <DAO_TREASURY_ADDR> --amount 10 --token ANON --spend-hook $(moonshine dao spend-hook) --user-data <DAO_BULLA>

# Money token / DAO / Deployooor (fee paid from a DRK coin; sync after mining/confirming)
moonshine token generate-mint --alias ANON
moonshine token mint ANON 100 "$(moonshine address list | awk '/★/{print $1; exit}')"
moonshine dao create GuideDAO 20 10 10 0.67 ANON
moonshine dao mint GuideDAO
moonshine dao spend-hook
moonshine dao balance GuideDAO
moonshine contract generate-deploy
moonshine contract deploy <CONTRACT_ID> ./my_contract.wasm
```

Full token/DAO walkthrough (including DAO treasury deposits, proposals, and votes): [docs/deploy-a-dao.md](docs/deploy-a-dao.md).

---

## CLI command tree

```text
moonshine
├── wallet create | import | export | delete | list | info
├── address list | new | default
├── balance
├── coins list
├── tx send [--to <ADDR>] [--amount <VAL>] [--token <TOK>] [--spend-hook <HOOK>] [--user-data <DATA>] | list | show | broadcast | inspect
├── sync [--force-trial] [--unifomr] [--rebuild-merkle]
├── rescan
├── status
├── config [--server-url <URL>] [--network <NET>] [--use-tor <BOOL>] [--tls-pin <HEX>] [--experimental-unifomr <BOOL>]
├── doctor
├── prune
├── token generate-mint | import | list | mint | freeze
├── dao create | import | list | spend-hook | balance | calls | view | proposals | mint
├── contract generate-deploy | list | events | deploy | lock
└── version
```

---

## Features

### Sync & OMR

| Feature | Status | Notes |
|---------|--------|-------|
| **Trial decrypt (default)** | ✅ | Padded compact outputs, nullifiers, token mints, compact DAO calls |
| **Token mint / freeze / send** | ✅ | `token generate-mint` / `mint` / `freeze` via Money + native fee; custom token transfers with spend-hooks |
| **DAO create / mint / treasury** | ✅ | `dao create` / `mint` / `spend-hook` / `balance` / `proposals`; automatic DAO treasury trial decryption on sync |
| **Contract deploy / lock** | ✅ | Deployooor authority + WASM `deploy` / `lock` through lightwalletd |
| **Clue PK register on sync** | ✅ | Fail-closed if registration fails for all addresses. Session cache is FIFO-capped at 10,000 ids |
| **UnifOMR send clue** | ✅ | `GetCluePublicKey` → `build_omr_clue_from_pk`; abort if unavailable. `tx send --no-omr` omits the clue for trial-decrypt receive. Change outputs get `extra_omr_clues`, but strict sync still does not make that change spendable. Run `sync --force-trial` after the change is in a block |
| **Multi-input send** | ✅ | The transfer builder spends the fewest unhooked coins that cover the amount and fee, then shuffles outputs. A send uses at most 8 inputs (Halo2 burns). Above that the wallet returns an error asking you to consolidate coins |
| **Localnet UnifOMR (2026-10-21)** | ✅ | 100/100 each way with Android and with desktop. `--no-omr` payments were received by those wallets under trial decrypt |
| **Payment memo on wire** | ✅ | `--memo` (≤255 UTF-8 bytes) → plain user text in recipient `MoneyNote::memo`; encrypted OMR metadata sent separately in `omr_metadata_enc` when experimental UnifOMR is active |
| **UnifOMR detection key** | ✅ | Derived from the primary wallet secret (matching registered clue key) and streamed in 1 MiB chunks |
| **Local BlockCache** | ✅ | Sparse/PIR compact blocks cached beside wallet DB |
| **Instant Sync Checkpoints** | ✅ | Fast Merkle tree restore from authenticated `CheckpointSnapshot` (see [docs/instant-sync-strategy.md](docs/instant-sync-strategy.md)) |
| **Proto Version Lockstep** | ✅ | Client proto **2.1.0**. A 1.x or 3.x server is a hard mismatch; an empty server version is a mismatch |
| **OMR Err → no silent trial (S15)** | ✅ | Tip not advanced on OMR **error** |
| **Experimental UnifOMR** | optional | `sync --unifomr` or `experimental_unifomr = true`. Off by default |
| **Tip regression rewind** | ✅ | Rewinds sync height when tip < last synced. Deleted note/tx counts come from SQLite `execute` rowcounts, not log-line length |
| **`chain_name` network guard** | ✅ | Must match config `network` |
| **TLS pin remote HTTPS** | ✅ | `tls_pin_sha256` + `PinnedVerifier` (leaf DER SHA-256); remote cleartext refused |
| **Address validation** | ✅ | DarkFi checksum addresses |
| **Network-aware addresses** | ✅ | Create/import use config network |

### Encryption & at-rest

| Feature | Status | Notes |
|---------|--------|-------|
| **SQLCipher DB (S14)** | ✅ | `PRAGMA key` from `MOONSHINE_WALLET_PASS` (required for new wallets; legacy `{db}.pass` 0600 still opens) |
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
- Cross-client crypto parity: Param2 RLWE `n=1024`, discrete Gaussian `σ=0.5` (`CLUE_ERROR_BOUND=84`, `r′=149`, `ℓ=2`), signed AHE, length-prefixed SealPIR limbs
- Flow: RegisterCluePublicKey → GetClue → SendTransaction(omr_clue) → GetUnifOmrDigest → FetchPirBatch
- Default sync is trial decryption. `--unifomr` is experimental and unmaintained until DarkFi mainnet contracts are live.
- Send fails closed unless GetClue **ownership proof** verifies (rejects directory decoys)
- First-run default LWD: remote HTTPS endpoint with leaf-cert `tls_pin_sha256` and Tor enabled (`use_tor = true`). Override with `--server http://127.0.0.1:9067` for local loopback (Tor is auto-skipped for loopback).
- Limits: [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md) (Param2 active)
- MVP fork archive: [`docs/unifomr_mvp_archive.md`](docs/unifomr_mvp_archive.md)
- Checklist: [`docs/verification-checklist.md`](docs/verification-checklist.md)

## Known issues

1. **Change is spendable after the next sync.** Change from the previous send is visible after the next default trial-decrypt sync includes that block.
2. **Experimental UnifOMR can hide funds.** `--unifomr` only sees payments whose clue was registered on this lightwalletd. Leave it off to receive `drk` and other clue-less transfers.
3. **`git.dark.fi` returns HTTP 504** and does not publish pin `b87318e80`. Clone `nighthawk24/darkfi` (or symlink the Android `third_party/darkfi`). `kvdb-overlay`, RandomX, and `rust-url` are fetched from GitLab, Codeberg, and GitHub.

---

## Related projects

| Sibling directory | Role |
|-------------------|------|
| `../darkfi-nighthawk-testnet` | DarkFi SDK pin `b87318e80` (symlink to `nighthawk-android-wallet/third_party/darkfi`) |
| `../darkfi-lightwalletd` | gRPC lightwalletd + shared UnifOMR |
| `../blackhawk` | Shared UniFFI + C-ABI core crate (Android / iOS / desktop) |
| `../nighthawk-android-wallet` | Android wallet (`third_party/darkfi` = same pin) |
| `../nighthawk-ios-wallet` | iOS wallet |
| `../nighthawk-app-desktop` | Desktop wallet (Tauri) |

---

## License

AGPL-3.0-only (see source headers).
