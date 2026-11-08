# Moonshine Wallet CLI

**Moonshine** is a private, lightweight CLI light wallet for the **DarkFi** blockchain. It connects to **`darkfi-lightwalletd`** over gRPC. The default sync is padded trial decryption. Experimental UnifOMR is off unless you pass `--unifomr` or set `experimental_unifomr = true`.

**3.01.06** (crate semver **3.1.6**): Speaks lightwalletd proto 2.1.0. A normal `moonshine sync` pulls compact Money notes, DAO calls, and auth-token events from **`darkfi-lightwalletd`**, trial-decrypts them into the local SQLCipher wallet (same scan semantics as `drk`, without full-chain validation like `darkfid`), and deletes processed compact blocks from the encrypted UniFFI-format cache. Beyond sync and DRK send, Moonshine can mint/freeze Money tokens, create/mint DAOs, and deploy/lock Deployooor WASM authorities through the same lightwalletd `SendTransaction` path (native fee attached locally). `moonshine sync --unifomr` remains experimental and is not maintained until DarkFi mainnet contracts are live. Tor is Arti 0.48, with a fresh circuit per dial. A send spends one coin, the largest that covers the amount plus fee. DarkFi checkout `44ec78b6e` (`nighthawk-testnet`, path dependency). Testnet explorer: [https://explorer.testnet.dark.fi](https://explorer.testnet.dark.fi).

> **Trial decryption is the default.** Payments from `drk`, Nighthawk, and Moonshine are found from the note itself. `--force-trial` still forces a full pass. `--unifomr` registers clue keys and can miss funds when the other wallet is not registered on this same lightwalletd.

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
- [Create a token and a DAO](docs/deploy-a-dao.md)

---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Rust** stable | [rustup](https://rustup.rs/) |
| **`protoc`** | On `PATH` |
| **Sibling `darkfi-nighthawk-testnet`** | Directory name is literal. Pin `44ec78b6e` (full `44ec78b6efbf1d3e797f99bffe95195994b2488d`, nighthawk24 `nighthawk-testnet`). A `darkfi` checkout on master is **not** enough, and `git.dark.fi` returns HTTP 504 and does not have this pin. You may `ln -s nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet` — that tree is the same pin. |
| **Sibling `darkfi-lightwalletd`** | Proto from `../darkfi-lightwalletd/proto/lightwallet.proto` |
| **Running lightwalletd** | Local or remote before `moonshine sync` |

Clone the path dependencies as **sibling directories** (names matter — see `Cargo.toml` / `build.rs`):

```text
parent/
  darkfi-nighthawk-testnet/ # MUST be this name — pin 44ec78b6e, not git.dark.fi master
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
# See docs/darkfi-pin.md — current SHA 44ec78b6efbf1d3e797f99bffe95195994b2488d
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

moonshine wallet create --name main
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
| **One input per send** | ✅ | Largest coin that covers amount + fee. A two-input proof is not built; darkfid rejects it |
| **Localnet UnifOMR (2026-10-21)** | ✅ | 100/100 each way with Android and with desktop. `--no-omr` payments were received by those wallets under trial decrypt |
| **Payment memo on wire** | ✅ | `--memo` → OMR-aware bytes in recipient `MoneyNote::memo` (not local-only) |
| **Multi detection_keys** | ✅ | Up to 16 wallet secrets in `GetUnifOmrDigest` |
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
- Default sync is trial decryption. `--unifomr` is experimental and unmaintained until DarkFi mainnet contracts are live.
- Send fails closed unless GetClue **ownership proof** verifies (rejects directory decoys)
- First-run default LWD: loopback `http://127.0.0.1:9067` (Tor off). Remote HTTPS still needs `tls_pin_sha256` + Tor if you want it.
- Limits: [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md) (Param2 active)
- MVP fork archive: [`docs/unifomr_mvp_archive.md`](docs/unifomr_mvp_archive.md)
- Checklist: [`docs/verification-checklist.md`](docs/verification-checklist.md)

## Known issues

1. **One input per transaction.** darkfid rejected a two-input transfer proof on the 2026-10-21 localnet. Selection spends a single coin that covers the amount plus the 0.05 DRK fee. It does not combine smaller coins. If no such coin is visible yet, the send stops before broadcast.
2. **One coin must cover the amount plus fee.** Change from the previous send is visible after the next default trial-decrypt sync includes that block. A second coin is not combined into the proof.
3. **Experimental UnifOMR can hide funds.** `--unifomr` only sees payments whose clue was registered on this lightwalletd. Leave it off to receive `drk` and other clue-less transfers.
4. **`git.dark.fi` returns HTTP 504** and does not publish pin `44ec78b6e`. Clone `nighthawk24/darkfi` (or symlink the Android `third_party/darkfi`). `kvdb-overlay`, RandomX, and `rust-url` are fetched from GitLab, Codeberg, and GitHub.

---

## Related projects

| Sibling directory | Role |
|-------------------|------|
| `../darkfi-nighthawk-testnet` | DarkFi SDK pin `44ec78b6e` (symlink to `nighthawk-android-wallet/third_party/darkfi`) |
| `../darkfi-lightwalletd` | gRPC lightwalletd + shared UnifOMR |
| `../darkfi-mobile-ffi` | Shared UniFFI crate (Android / iOS / desktop) |
| `../nighthawk-android-wallet` | Android wallet (`third_party/darkfi` = same pin) |
| `../nighthawk-ios-wallet` | iOS wallet |
| `../nighthawk-app-desktop` | Desktop wallet (Tauri) |

---

## License

AGPL-3.0-only (see source headers).
