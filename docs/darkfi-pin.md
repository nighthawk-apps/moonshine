# DarkFi revision pin (Moonshine)

Moonshine path-depends on sibling `../darkfi` and `../darkfi-lightwalletd`.

For reproducible builds, check out DarkFi at the SHA in:

```text
../darkfi-lightwalletd/scripts/darkfi.rev
```

```bash
cd ../darkfi-lightwalletd
FORCE_DARKFI_PIN=1 ./scripts/fetch-darkfi.sh
```

Current shared tip (pre-release): `a76639f020a55473ee786deb584d603d968d4db6`.

## Wallet crypto note

| Client | Wallet DB |
|--------|-----------|
| Moonshine | Own SQLCipher pruned SQLite (`rusqlite` + `PRAGMA key`) |
| Android / iOS / desktop UniFFI | Upstream `bin/drk` turso + experimental aegis256 |

Moonshine does **not** vendor or overlay `bin/drk`.
