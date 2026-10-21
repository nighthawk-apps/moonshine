# DarkFi revision pin (Moonshine)

Moonshine path-depends on sibling `../darkfi-nighthawk-testnet` (directory name is
literal) and `../darkfi-lightwalletd`. A checkout named `darkfi` on master will not
resolve. Reuse the Android pin:

```bash
ln -sfn new-nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet
```

Upstream DarkFi is [https://git.dark.fi/darkrenaissance/darkfi](https://git.dark.fi/darkrenaissance/darkfi). Do not clone the GitHub mirror (`github.com/darkrenaissance/darkfi`). Do not pin git.dark.fi master — that tree is Arti 0.42 without the keccak overlay. The Nighthawk pin below is not published on git.dark.fi; CI checks it out from `nighthawk24/darkfi` (`nighthawk-testnet`, Arti 0.45 + keccak + kvdb-overlay).

Current pin: `e4e624179305952c95af1360100d379a81272586` (`nighthawk-testnet`). The crates path-depend on `../darkfi-nighthawk-testnet`, so this is the checkout those builds use, not a git `rev`.

## Wallet crypto note

| Client | Wallet DB |
|--------|-----------|
| Moonshine | Own SQLCipher pruned SQLite (`rusqlite` + `PRAGMA key`) |
| Android / iOS / desktop UniFFI | Upstream `bin/drk` turso + experimental aegis256 |

Moonshine does **not** vendor or overlay `bin/drk`.
