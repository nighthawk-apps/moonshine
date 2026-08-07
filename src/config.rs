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

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration options for Moonshine CLI.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    /// Remote lightwalletd server gRPC endpoint.
    pub server_url: String,
    /// Blockchain network configuration (mainnet or testnet).
    pub network: String,
    /// Optional TLS certificate pin (SHA-256 hex of leaf cert DER).
    /// Required for non-localhost server_url. Computed with:
    ///   openssl x509 -in lightwalletd.crt -outform DER | openssl dgst -sha256
    #[serde(default)]
    pub tls_pin_sha256: Option<String>,
    /// Route remote lightwalletd traffic through the embedded Tor client
    /// (arti). Default ON — hides the wallet's IP from the server operator.
    /// Localhost endpoints always connect directly.
    #[serde(default = "default_use_tor")]
    pub use_tor: bool,
}

fn default_use_tor() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Studio testnet LWD via ngrok (see ~/.local/share/darkfi/studio-lwd-endpoint.env).
            server_url: "https://epidermis-sandbox-marshland.ngrok-free.dev".to_string(),
            network: "testnet".to_string(),
            tls_pin_sha256: Some(
                "9f8f3877f312cb48e4d8d050b5c7b70f6144f1c31812d7ec299c32793a274985".to_string(),
            ),
            // Direct path to ngrok; Tor can be re-enabled in config.toml.
            use_tor: true,
        }
    }
}

impl Config {
    /// Get the path of the config file.
    pub fn config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Path::new(&home)
            .join(".config")
            .join("moonshine")
            .join("config.toml")
    }

    /// Load the configuration file, creating a default one if it doesn't exist.
    pub fn load() -> Self {
        let path = Self::config_path();
        if !path.exists() {
            let default_config = Self::default();
            if let Err(e) = default_config.save() {
                eprintln!("Warning: Failed to save default config: {}", e);
            }
            return default_config;
        }

        match fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to parse config file: {}. Using defaults.",
                        e
                    );
                    Self::default()
                }
            },
            Err(e) => {
                eprintln!(
                    "Warning: Failed to read config file: {}. Using defaults.",
                    e
                );
                Self::default()
            }
        }
    }

    /// Save the configuration to the config path.
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let serialized = toml::to_string_pretty(self)?;
        fs::write(path, serialized)?;
        Ok(())
    }
}
