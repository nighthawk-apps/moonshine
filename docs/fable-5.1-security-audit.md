# Fable 5.1 security audit — moonshine

**Audit date:** 2026-09-20  
**Model:** Claude Fable 5.1  
**Review date:** 2026-09-21  
**Shipped revision:** `0441a57` (v3.0.15)  

Full auditor transcripts:

- [`fable-5.1-audit-desktop-moonshine-lwd-source.md`](fable-5.1-audit-desktop-moonshine-lwd-source.md) — subagent `7747fe26`
- [`fable-5.1-audit-unifomr-explore-source.md`](fable-5.1-audit-unifomr-explore-source.md) — subagent `0659fd0c`

---

## MUST-FIX status (this repo)

| ID | Finding | Status | Evidence |
|----|---------|--------|----------|
| M1 | TTY check after DB+key written | **FIXED** | `wallet.rs` refuses before opening DB when stderr is not a TTY |
| M2 | `Config::default()` had `use_tor: false` | **FIXED** | `config.rs` `use_tor: default_use_tor()` → `true` |
| M3 | Non-ASCII memo / address print panic | **FIXED** | Display paths use safe UTF-8 handling (v3.0.15) |
| M4 | `--token` ignored; always DRK | **FIXED** | `main.rs` rejects non-DRK `--token` with clear error |
| Doc budgets | `unifomr_mvp_limits.md` stale MiB figures | **FIXED** | Aligned docs with LWD 160 MiB / ~120 MiB keys and key_version u64 LE |
| Strict OMR parity | Moonshine TD-only vs Nighthawk PIR+TD | **FIXED** | Documented intentional privacy equivalence and bandwidth trade-off in `unifomr_mvp_limits.md` |

## SHOULD-FIX (deferred)

Constant Argon2 salt; home-rolled wrap vs AEAD; plaintext MSK forever; `.wrapkey` beside DB; unchecked u64 adds; unwraps on decode; swallow `mark_spent`; no `connect_timeout`; floating LWD CI ref; `delete` leaves `last-tx.hex` — see source audit § M5–M15.
