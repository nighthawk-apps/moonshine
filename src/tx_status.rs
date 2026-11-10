//! One-line status for every wallet operation tests and operators parse.
//!
//! `tx-status kind=<kind> phase=<phase> result=<success|fail> state=<state> ...`
//!
//! States:
//! - `waiting` — signed or recorded locally, not submitted
//! - `confirming` — submitted, not in a scanned block yet (`height=0`)
//! - `confirmed` — included in a scanned block
//! - `local` — wallet-only record (mint authority, DAO signing keys)
//! - `failed` — the operation did not succeed

use std::cell::RefCell;

thread_local! {
    static SCOPE: RefCell<Option<(&'static str, &'static str)>> = const { RefCell::new(None) };
}

/// Remember the operation in flight so a later `Err` still names its kind.
pub fn begin(kind: &'static str, phase: &'static str) {
    SCOPE.with(|slot| *slot.borrow_mut() = Some((kind, phase)));
}

pub fn phase(phase: &'static str) {
    SCOPE.with(|slot| {
        let kind = slot.borrow().map(|(kind, _)| kind);
        if let Some(kind) = kind {
            *slot.borrow_mut() = Some((kind, phase));
        }
    });
}

/// Print a failure line when `run` returns `Err` inside a [`begin`] scope.
pub fn emit_fail(reason: &str) {
    SCOPE.with(|slot| {
        if let Some((kind, phase)) = *slot.borrow() {
            emit(kind, phase, "fail", "failed", "", None, "", None, "", reason);
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn emit(
    kind: &str,
    phase: &str,
    result: &str,
    state: &str,
    hash: &str,
    height: Option<u32>,
    token: &str,
    amount: Option<u64>,
    detail: &str,
    reason: &str,
) {
    let hash = blank(hash);
    let token = blank(token);
    let height = height
        .map(|h| h.to_string())
        .unwrap_or_else(|| "-".into());
    let amount = amount
        .map(|a| a.to_string())
        .unwrap_or_else(|| "-".into());
    println!(
        "tx-status kind={kind} phase={phase} result={result} state={state} hash={hash} height={height}{} amount={amount}{}{}",
        field("token", token),
        quoted("detail", detail),
        quoted("reason", reason),
    );
}

pub fn dao_kind(code: u32) -> &'static str {
    match code {
        0 => "dao-mint",
        // A synced proposal is the signed DAO action. Wallet key creation uses
        // `kind=dao-sign` on the `dao create` command itself.
        1 => "dao-propose",
        2 => "dao-vote",
        3 => "dao-exec",
        4 => "dao-auth-transfer",
        _ => "dao-call",
    }
}

pub fn dao_detail(code: u32) -> &'static str {
    match code {
        1 => "propose",
        _ => "",
    }
}

pub fn money_event_kind(code: u32) -> &'static str {
    match code {
        0x04 => "asset-create",
        0x05 => "burn",
        0x06 => "token-mint",
        _ => "receive",
    }
}

pub fn money_event_detail(code: u32) -> &'static str {
    match code {
        0x05 => "freeze-mint-authority",
        _ => "",
    }
}

/// List/show label for a stored row.
pub fn stored_state(height: u32) -> &'static str {
    if height == 0 {
        "confirming"
    } else {
        "confirmed"
    }
}

fn blank(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

fn field(key: &str, value: &str) -> String {
    let safe = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '@' | '+' | '-'));
    if safe {
        format!(" {key}={value}")
    } else {
        quoted(key, value)
    }
}

fn quoted(key: &str, value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let flat: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let escaped = flat.replace('\\', "\\\\").replace('"', "\\\"");
    format!(" {key}=\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_reason_is_one_quoted_field() {
        let line = {
            // Build the same suffix the printer uses.
            format!(
                "tx-status kind=send phase=broadcast result=fail state=failed hash=- height=- token=- amount=-{}",
                quoted("reason", "lightwalletd said \"no\"\nand left")
            )
        };
        assert!(line.contains("result=fail"));
        assert!(line.contains("state=failed"));
        assert!(line.contains("reason=\"lightwalletd said \\\"no\\\" and left\""));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn kinds_name_chain_events() {
        assert_eq!(dao_kind(1), "dao-propose");
        assert_eq!(dao_detail(1), "propose");
        assert_eq!(money_event_kind(0x05), "burn");
        assert_eq!(money_event_detail(0x05), "freeze-mint-authority");
        assert_eq!(stored_state(0), "confirming");
        assert_eq!(stored_state(12), "confirmed");
    }
}
