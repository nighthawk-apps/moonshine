/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

//! Decimal DRK amounts → atomic units without floating point.

use darkfi::util::parse::{decode_base10, encode_base10};

/// DarkFi native token display decimals (1 DRK = 10^8 atomic).
pub const DRK_DECIMALS: usize = 8;

/// Parse a user amount such as `0.18` or `1` into atomic units.
pub fn parse_drk_atomic(amount: &str) -> Result<u64, String> {
    let trimmed = amount.trim();
    if trimmed.is_empty() {
        return Err("amount must not be empty".into());
    }
    decode_base10(trimmed, DRK_DECIMALS, false)
        .map_err(|e| format!("invalid amount `{trimmed}`: {e}"))
}

/// Format atomic units as a decimal DRK string (display only).
pub fn format_drk_atomic(atomic: u64) -> String {
    encode_base10(atomic, DRK_DECIMALS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_amounts() {
        assert_eq!(parse_drk_atomic("1").unwrap(), 100_000_000);
        assert_eq!(parse_drk_atomic("0.18").unwrap(), 18_000_000);
        assert_eq!(parse_drk_atomic("0.00000001").unwrap(), 1);
    }

    #[test]
    fn rejects_zero_and_empty() {
        assert!(parse_drk_atomic("").is_err());
        assert_eq!(parse_drk_atomic("0").unwrap(), 0);
    }

    #[test]
    fn does_not_use_binary_float() {
        // 0.29 is a classic f64 * 1e8 trap (28999999).
        assert_eq!(parse_drk_atomic("0.29").unwrap(), 29_000_000);
    }

    #[test]
    fn format_roundtrip() {
        assert_eq!(format_drk_atomic(18_000_000), "0.18");
    }
}
