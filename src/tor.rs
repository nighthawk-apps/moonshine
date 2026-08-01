/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Embedded Arti (Tor) client for lightwalletd gRPC.
//!
//! Moonshine routes all remote lightwalletd traffic through an in-process
//! [`arti_client::TorClient`] by default (`use_tor = true` in config). The
//! Tor circuit hides the wallet's IP from the lightwalletd operator; TLS
//! certificate pinning on top of the Tor stream keeps server authentication
//! identical to the direct path.
//!
//! Localhost endpoints (`127.0.0.1` / `localhost` / `[::1]`) never go
//! through Tor — they are local development / private full-node setups.
//!
//! The Tor client bootstraps lazily on first use (directory fetch + circuit
//! build, typically 5–30 s on first launch; cached descriptors make later
//! runs fast) and is shared for the process lifetime.
//!
//! Fail-closed: if the bootstrap or the Tor dial fails, the connection
//! errors out — traffic is never silently downgraded to a direct connection.

use arti_client::{TorClient, TorClientConfig};
use tokio::sync::OnceCell;
use tor_rtcompat::tokio::TokioRustlsRuntime;

static TOR: OnceCell<TorClient<TokioRustlsRuntime>> = OnceCell::const_new();

/// Get the shared, bootstrapped Tor client, bootstrapping on first call.
pub async fn tor_client() -> Result<TorClient<TokioRustlsRuntime>, String> {
    let client = TOR
        .get_or_try_init(|| async {
            eprintln!("Bootstrapping embedded Tor (arti) — first run can take up to 30s...");
            let runtime = TokioRustlsRuntime::current()
                .map_err(|e| format!("Tor runtime init failed: {e}"))?;
            let client = TorClient::with_runtime(runtime)
                .config(TorClientConfig::default())
                .create_bootstrapped()
                .await
                .map_err(|e| format!("Tor bootstrap failed: {e}"))?;
            eprintln!("Tor circuit established.");
            Ok::<_, String>(client)
        })
        .await?;
    Ok(client.clone())
}

/// Dial `host:port` through Tor. Returns an [`arti_client::DataStream`],
/// which implements tokio `AsyncRead`/`AsyncWrite` and can carry TLS.
pub async fn connect(host: &str, port: u16) -> Result<arti_client::DataStream, String> {
    let client = tor_client().await?;
    client
        .connect((host, port))
        .await
        .map_err(|e| format!("Tor connect to {host}:{port} failed: {e}"))
}
