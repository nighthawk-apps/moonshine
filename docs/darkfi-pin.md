# DarkFi revision pin (Moonshine)

Moonshine path-depends on sibling `../darkfi-nighthawk-testnet` (directory name is
literal) and `../darkfi-lightwalletd`. A checkout named `darkfi` on master will not
resolve. Reuse the Android pin:

```bash
ln -sfn nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet
```

Do not clone [git.dark.fi/darkrenaissance/darkfi](https://git.dark.fi/darkrenaissance/darkfi). That host returns HTTP 504, and this pin is not published there. Do not pin git.dark.fi master — that tree is Arti 0.42 without the keccak overlay. CI checks this pin out from `nighthawk24/darkfi` (`nighthawk-testnet`, Arti 0.45 + keccak + kvdb-overlay).

Cargo git deps inside the pin (also HTTP 504 on git.dark.fi):

| Crate | Fetch |
|-------|--------|
| `kvdb-overlay` `accd2689f42e17d8db05294fbe9c3dac1ef307f4` | `https://gitlab.com/nighthawk24/kvdb-overlay` |
| RandomX `0e31d5a` | `https://codeberg.org/darkrenaissance/RandomX` |
| `rust-url` branch `v258` | `https://github.com/darkrenaissance/rust-url` |

Current pin: `0e87090e9aa550d046c707b74ef5869269205f83` (`nighthawk-testnet`). The crates path-depend on `../darkfi-nighthawk-testnet`, so this is the checkout those builds use, not a git `rev`.

## Wallet crypto note

| Client | Wallet DB |
|--------|-----------|
| Moonshine | Own SQLCipher pruned SQLite (`rusqlite` + `PRAGMA key`) |
| Android / iOS / desktop UniFFI | Upstream `bin/drk` turso + experimental aegis256 |

Moonshine does **not** vendor or overlay `bin/drk`.
