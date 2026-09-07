# DarkFi revision pin (Moonshine)

Moonshine path-depends on sibling `../darkfi-nighthawk-testnet` (nighthawk24 `nighthawk-testnet` branch) and `../darkfi-lightwalletd`.

Do not point at `darkrenaissance/darkfi` master — that tree is Arti 0.42 without the keccak overlay. The nighthawk24 branch is Arti 0.45 + keccak + latest master (kvdb-overlay).

Current pin: `327fa9f134fc756b84be2ce327afaae1cd41a956` (`nighthawk-testnet`).

## Wallet crypto note

| Client | Wallet DB |
|--------|-----------|
| Moonshine | Own SQLCipher pruned SQLite (`rusqlite` + `PRAGMA key`) |
| Android / iOS / desktop UniFFI | Upstream `bin/drk` turso + experimental aegis256 |

Moonshine does **not** vendor or overlay `bin/drk`.
