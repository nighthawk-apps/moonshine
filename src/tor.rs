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
//! Each dial uses [`TorClient::isolated_client`], so sync, `GetCluePublicKey`,
//! and `SendTransaction` (separate `LightwalletClient`s) do not share an exit
//! circuit. `.onion` addresses are allowed. State and cache live under
//! `~/.config/moonshine/arti` so later launches reuse directory documents.
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

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::{StreamPrefs, TorClient, TorClientConfig};
use tokio::sync::OnceCell;
use tor_rtcompat::tokio::TokioRustlsRuntime;

static TOR: OnceCell<Arc<TorClient<TokioRustlsRuntime>>> = OnceCell::const_new();

/// `~/.config/moonshine/arti`, beside `config.toml`.
pub fn arti_storage_dir() -> PathBuf {
    crate::config::Config::config_path()
        .parent()
        .map(|dir| dir.join("arti"))
        .unwrap_or_else(|| PathBuf::from("arti"))
}

/// Arti refuses state directories that are group- or world-accessible.
fn restrict_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("arti dir {}: {e}", path.display()))?;
    let mut perms = fs::metadata(path)
        .map_err(|e| format!("arti dir {}: {e}", path.display()))?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms).map_err(|e| format!("arti dir {}: {e}", path.display()))
}

fn arti_config() -> Result<TorClientConfig, String> {
    let base = arti_storage_dir();
    let state_dir = base.join("state");
    let cache_dir = base.join("cache");
    restrict_dir(&base)?;
    restrict_dir(&state_dir)?;
    restrict_dir(&cache_dir)?;
    let mut builder = TorClientConfigBuilder::from_directories(state_dir, cache_dir);
    builder.address_filter().allow_onion_addrs(true);
    builder
        .build()
        .map_err(|e| format!("Tor config (onion must be enabled): {e}"))
}

/// Get the shared, bootstrapped Tor client, bootstrapping on first call.
pub async fn tor_client() -> Result<Arc<TorClient<TokioRustlsRuntime>>, String> {
    let client = TOR
        .get_or_try_init(|| async {
            eprintln!("Bootstrapping embedded Tor (arti) — first run can take up to 30s...");
            // Arti's rustls stack needs one process-wide provider. Wallet TLS
            // pins its own provider per handshake, so this only covers Tor.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let runtime = TokioRustlsRuntime::current()
                .map_err(|e| format!("Tor runtime init failed: {e}"))?;
            let config = arti_config()?;
            // Arti ≥0.45 returns Arc<TorClient<_>> from create_bootstrapped.
            let client = TorClient::with_runtime(runtime)
                .config(config)
                .create_bootstrapped()
                .await
                .map_err(|e| format!("Tor bootstrap failed: {e}"))?;
            eprintln!("Tor circuit established.");
            Ok::<_, String>(client)
        })
        .await?;
    Ok(Arc::clone(client))
}

/// Dial `host:port` through a fresh isolated Tor circuit.
///
/// Returns an [`arti_client::DataStream`], which implements tokio
/// `AsyncRead`/`AsyncWrite` and can carry TLS. `.onion` targets are accepted.
pub async fn connect(host: &str, port: u16) -> Result<arti_client::DataStream, String> {
    let client = tor_client().await?;
    let isolated = client.isolated_client();
    let mut prefs = StreamPrefs::new();
    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
    isolated
        .connect_with_prefs((host, port), &prefs)
        .await
        .map_err(|e| format!("Tor connect to {host}:{port} failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arti_config_enables_onion_with_persistent_dirs() {
        let cfg = arti_config().expect("onion-capable Arti config");
        let _ = cfg;
        let dir = arti_storage_dir();
        assert!(dir.join("state").is_dir());
        assert!(dir.join("cache").is_dir());
    }

    /// Live check that Arti 0.48 bootstraps and an isolated circuit can dial.
    #[tokio::test]
    #[ignore = "dials the Tor network"]
    async fn isolated_circuit_dials_through_tor() {
        let stream = connect("check.torproject.org", 443)
            .await
            .expect("isolated Tor dial");
        drop(stream);
    }
}
