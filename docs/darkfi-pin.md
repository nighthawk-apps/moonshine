# DarkFi revision pin (Moonshine)

Moonshine path-depends on sibling `../darkfi-nighthawk-testnet` (directory name is
literal) and `../darkfi-lightwalletd` (which path-depends on `../blackhawk/crates/blackhawk-unifomr` when `fhe-omr` is enabled). A checkout named `darkfi` on master will not
resolve. Reuse the Android pin:

```bash
ln -sfn nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet
```

Do not clone [git.dark.fi/darkrenaissance/darkfi](https://git.dark.fi/darkrenaissance/darkfi). That host returns HTTP 504, and this pin is not published there. Do not pin git.dark.fi master — that tree is an older Arti without the keccak overlay. CI checks this pin out from `nighthawk24/darkfi` (`nighthawk-testnet`, Arti 0.48 + keccak + kvdb-overlay). The pin includes tx-local fees: a fee call spends a change output in the same transaction when that output covers the fee.

Cargo git deps inside the pin (also HTTP 504 on git.dark.fi):

| Crate | Fetch |
|-------|--------|
| `kvdb-overlay` `accd2689f42e17d8db05294fbe9c3dac1ef307f4` | `https://gitlab.com/nighthawk24/kvdb-overlay` |
| RandomX `0e31d5a` | `https://codeberg.org/darkrenaissance/RandomX` |
| `rust-url` branch `v258` | `https://github.com/darkrenaissance/rust-url` |

Current pin: `b87318e80968ea071fbd3a56eb1ea17110252753` (`nighthawk-testnet`, same commit as Android `third_party/darkfi`). It builds on `191941936` (`9d7ceaf77` + `6e61deb26` recipient memos + spent-nullifier skip) with upstream P2P/TLS timeout, `SocketAddr` fallback, event-graph reconnect/DAG catchup, checkpoint header, and RFC 1929 SOCKS5 auth fixes. Moonshine passes the recipient memo into the transfer builder, so a checkout of `9d7ceaf77` or git.dark.fi master fails with `E0061` (13 arguments, 14 supplied). The crates path-depend on `../darkfi-nighthawk-testnet`, so this is the checkout those builds use, not a git `rev`.

## Wallet crypto note

| Client | Wallet DB |
|--------|-----------|
| Moonshine | Own SQLCipher pruned SQLite (`rusqlite` + `PRAGMA key`) |
| Android / iOS / desktop UniFFI | Upstream `bin/drk` turso + experimental aegis256 |

Moonshine does **not** vendor or overlay `bin/drk`.
