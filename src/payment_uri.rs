//! `drk:` payment invoices. Memo is UTF-8 then standard base64 so Nighthawk
//! desktop `parsePaymentUri` reads it back.

pub const MAX_PAYMENT_MEMO_BYTES: usize = 255;

pub fn build_payment_uri(address: &str, amount: Option<&str>, memo: Option<&str>) -> String {
    let mut query: Vec<String> = Vec::new();
    if let Some(amount) = amount.map(str::trim).filter(|s| !s.is_empty()) {
        query.push(format!("amount={amount}"));
    }
    if let Some(memo) = memo.map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = truncate_utf8(memo.as_bytes(), MAX_PAYMENT_MEMO_BYTES);
        query.push(format!("memo={}", percent_encode(&b64_encode(bytes))));
    }
    if query.is_empty() {
        format!("drk:{address}")
    } else {
        format!("drk:{address}?{}", query.join("&"))
    }
}

fn truncate_utf8(bytes: &[u8], max_bytes: usize) -> &[u8] {
    if bytes.len() <= max_bytes {
        return bytes;
    }
    let mut end = max_bytes;
    while end > 0 && bytes[end] & 0xc0 == 0x80 {
        end -= 1;
    }
    &bytes[..end]
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rest = data.len() - i;
    if rest == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoice_includes_amount_and_base64_memo() {
        let uri = build_payment_uri("drk1abc", Some("1.5"), Some("lunch"));
        assert!(uri.starts_with("drk:drk1abc?"));
        assert!(uri.contains("amount=1.5"));
        // "lunch" is bHVuY2g= ; '=' is percent-encoded for the query.
        assert!(uri.contains("memo=bHVuY2g%3D"));
    }

    #[test]
    fn bare_address_omits_query() {
        assert_eq!(build_payment_uri("drk1abc", None, Some("  ")), "drk:drk1abc");
    }
}
