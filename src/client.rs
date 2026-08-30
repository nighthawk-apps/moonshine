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

use std::error::Error;
use std::sync::Arc;
use tonic::transport::Channel;

pub mod proto {
    tonic::include_proto!("darkfi.lightwallet");
}

use proto::dark_fi_light_wallet_client::DarkFiLightWalletClient;

/// Param2 UnifOMR detection keys are ~120 MiB on the wire (D=4096, n=1024,
/// 3×40-bit moduli).  Keep headroom for digest responses.
const MAX_GRPC_MESSAGE_BYTES: usize = 160 * 1024 * 1024;

/// gRPC request timeout.  Param2 det-key upload (~120 MiB) + server-side FHE
/// detection + Tor latency easily exceed the tonic default (no timeout).
/// Must be ≥ lightwalletd `request_timeout_s` (1800). Per-message SIMD encode
/// of one Param2 chunk (D=4096, ℓ=2) can exceed 5 minutes.
const GRPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1800);

/// Exact-host loopback check. `https://localhost.evil.com` is remote.
fn host_is_loopback(server_url: &str) -> bool {
    let rest = server_url.split("://").nth(1).unwrap_or(server_url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = if let Some(inside) = hostport.strip_prefix('[') {
        inside.split(']').next().unwrap_or(inside)
    } else {
        hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport)
    };
    matches!(host, "127.0.0.1" | "::1" | "0:0:0:0:0:0:0:1")
        || host.eq_ignore_ascii_case("localhost")
}

fn with_large_messages(
    client: DarkFiLightWalletClient<Channel>,
) -> DarkFiLightWalletClient<Channel> {
    client
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES)
}

/// Boxed async byte stream: either a direct TCP stream or a Tor `DataStream`.
/// TLS (with the pinned verifier) runs on top of whichever transport is used.
trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncIo for T {}
type BoxedIo = Box<dyn AsyncIo>;

/// SHA-256 of leaf certificate DER — rejects non-matching certs (S8).
#[derive(Debug)]
struct PinnedVerifier {
    pinned_sha256: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(end_entity.as_ref());
        if hash.as_slice() == self.pinned_sha256 {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parse hex SHA-256 pin (64 hex chars) into 32 bytes.
pub fn parse_tls_pin_hex(hex_str: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let cleaned: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != 64 {
        return Err(format!(
            "tls_pin_sha256 must be 64 hex chars (SHA-256), got {}",
            cleaned.len()
        )
        .into());
    }
    let bytes = hex::decode(&cleaned)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Client to manage interaction with `lightwalletd` gRPC server.
pub struct LightwalletClient {
    pub server_url: String,
    pub(crate) client: Option<DarkFiLightWalletClient<Channel>>,
    /// SHA-256 hex of the expected leaf certificate DER.
    pub tls_pin_sha256: Option<String>,
    /// Route remote traffic through the embedded Tor client (default ON).
    /// Localhost endpoints always connect directly.
    pub use_tor: bool,
}

impl LightwalletClient {
    /// Create a client. `tls_pin` is the hex SHA-256 of the leaf cert DER
    /// (from config `tls_pin_sha256`). Required for remote HTTPS.
    ///
    /// Remote traffic is routed through the embedded Tor client by default;
    /// use [`Self::with_tor`] with `config.use_tor` to honor the user's config.
    pub fn new(server_url: &str, tls_pin: Option<String>) -> Self {
        Self {
            server_url: server_url.to_string(),
            client: None,
            tls_pin_sha256: tls_pin,
            use_tor: true,
        }
    }

    /// Set whether remote traffic is routed through the embedded Tor client.
    pub fn with_tor(mut self, use_tor: bool) -> Self {
        self.use_tor = use_tor;
        self
    }

    /// True if the server URL host is loopback (exact host, not a substring).
    fn is_localhost(&self) -> bool {
        host_is_loopback(&self.server_url)
    }

    /// Establish gRPC connection if not already connected.
    /// Enforces TLS + pin for non-localhost HTTPS (fail-closed).
    pub async fn connect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.client.is_some() {
            return Ok(());
        }

        let is_https = self.server_url.starts_with("https://");

        // S8: Enforce TLS for non-localhost connections
        if !self.is_localhost() {
            if !is_https {
                return Err(format!(
                    "Security: non-localhost server '{}' requires TLS (https://). \
                     Cleartext gRPC to remote servers is not allowed.",
                    self.server_url
                )
                .into());
            }
            // Fail closed: remote HTTPS without pin is refused.
            if self.tls_pin_sha256.is_none() {
                return Err(format!(
                    "Security: remote HTTPS server '{}' requires tls_pin_sha256 in config \
                     (SHA-256 of leaf cert DER). Refusing system-roots-only connect.",
                    self.server_url
                )
                .into());
            }
        }

        let client = if is_https {
            // Leaf-cert SHA-256 pin required for all HTTPS (working verifier).
            let pin_hex = self.tls_pin_sha256.as_ref().ok_or_else(|| {
                format!(
                    "HTTPS endpoint '{}' requires tls_pin_sha256 in config",
                    self.server_url
                )
            })?;
            let pin_hash = parse_tls_pin_hex(pin_hex)?;
            self.connect_with_pin(pin_hash).await?
        } else {
            let endpoint = tonic::transport::Endpoint::from_shared(self.server_url.clone())?
                .timeout(GRPC_TIMEOUT);
            let channel = endpoint.connect().await?;
            DarkFiLightWalletClient::new(channel)
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        };

        self.client = Some(client);
        Ok(())
    }

    async fn connect_with_pin(
        &self,
        pin_hash: [u8; 32],
    ) -> Result<DarkFiLightWalletClient<Channel>, Box<dyn Error>> {
        let uri = self.server_url.clone();
        let use_tor = self.use_tor && !self.is_localhost();
        let connector = tower::service_fn(move |dst: tonic::transport::Uri| {
            let pin_hash = pin_hash;
            async move {
                let host = dst
                    .host()
                    .ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing host")
                    })?
                    .to_string();
                let port = dst.port_u16().unwrap_or(443);

                // PRIVACY: dial through the embedded Tor client (fail-closed —
                // a Tor failure is an error, never a direct-connect downgrade).
                let tcp: BoxedIo = if use_tor {
                    let stream = crate::tor::connect(&host, port).await.map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e)
                    })?;
                    Box::new(stream)
                } else {
                    let addr = format!("{host}:{port}");
                    Box::new(tokio::net::TcpStream::connect(addr).await?)
                };

                let verifier = Arc::new(PinnedVerifier {
                    pinned_sha256: pin_hash,
                });
                let rustls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(std::io::Error::other)?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();

                let tls = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));
                let server_name = host.try_into().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid TLS server name: {e}"),
                    )
                })?;
                let tls_stream = tls.connect(server_name, tcp).await.map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("TLS handshake / pin check failed: {e}"),
                    )
                })?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls_stream))
            }
        });

        let channel = tonic::transport::Endpoint::from_shared(uri)?
            .timeout(GRPC_TIMEOUT)
            .connect_with_connector(connector)
            .await?;
        Ok(with_large_messages(DarkFiLightWalletClient::new(channel)))
    }

    /// Fetch server information and check status.
    pub async fn get_status(&mut self) -> Result<(), Box<dyn Error>> {
        println!(
            "Connecting to lightwalletd service at {}...",
            self.server_url
        );
        let info = self.get_light_info().await?;
        println!("Connected to lightwalletd server.");
        println!("  Version:       {}", info.version);
        println!("  Chain Name:    {}", info.chain_name);
        println!("  Block Height:  {}", info.block_height);
        println!("  OMR Supported: {}", info.omr_supported);
        Ok(())
    }

    /// Fetch `GetLightInfo` (chain_name used for network guard).
    pub async fn get_light_info(&mut self) -> Result<proto::LightInfo, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let response = client.get_light_info(proto::Empty {}).await?;
        Ok(response.into_inner())
    }

    /// Fetch chain tip.
    pub async fn get_chain_tip(&mut self) -> Result<proto::ChainTip, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let response = client.get_chain_tip(proto::Empty {}).await?;
        Ok(response.into_inner())
    }

    /// Fetch the Merkle tree state snapshot at a given block height.
    pub async fn get_tree_state(
        &mut self,
        height: u32,
    ) -> Result<proto::TreeState, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let response = client.get_tree_state(proto::BlockHeight { height }).await?;
        Ok(response.into_inner())
    }

    /// Send raw transaction with an optional UnifOMR clue.
    pub async fn send_transaction(
        &mut self,
        raw_tx: Vec<u8>,
        omr_clue: Vec<u8>,
        omr_metadata_enc: Vec<u8>,
    ) -> Result<proto::SendResponse, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let req = proto::RawTransaction {
            data: raw_tx,
            omr_clue,
            omr_clue_output_index: 0, // payment output
            omr_metadata_enc,
        };
        let response = client.send_transaction(req).await?;
        Ok(response.into_inner())
    }

    /// Stream compact blocks over a contiguous range.
    pub async fn get_block_range(
        &mut self,
        start: u32,
        end: u32,
    ) -> Result<tonic::Streaming<proto::CompactBlock>, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let req = proto::BlockRange {
            start_height: start,
            end_height: end,
        };
        let response = client.get_block_range(req).await?;
        Ok(response.into_inner())
    }

    /// Fetch a single compact block by height.
    pub async fn get_block(&mut self, height: u32) -> Result<proto::CompactBlock, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let response = client.get_block(proto::BlockHeight { height }).await?;
        Ok(response.into_inner())
    }

    /// Sparse fetch: compact blocks at specific heights.
    ///
    /// Prefers `GetCompactBlocksAtHeights`; falls back to N× `GetBlock` if the
    /// RPC is unimplemented / unavailable.
    pub async fn get_compact_blocks_at_heights(
        &mut self,
        heights: &[u32],
    ) -> Result<Vec<proto::CompactBlock>, Box<dyn Error>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }
        self.connect().await?;
        let mut client = self.client.clone().unwrap();

        let mut unique: Vec<u32> = heights.to_vec();
        unique.sort_unstable();
        unique.dedup();

        match client
            .get_compact_blocks_at_heights(proto::HeightList {
                heights: unique.clone(),
            })
            .await
        {
            Ok(response) => {
                let mut stream = response.into_inner();
                let mut blocks = Vec::new();
                while let Some(block) = futures::StreamExt::next(&mut stream).await {
                    blocks.push(block?);
                }
                Ok(blocks)
            }
            Err(status) => {
                let code = status.code();
                let fallback = code == tonic::Code::Unimplemented
                    || code == tonic::Code::NotFound
                    || status.message().to_lowercase().contains("unknown");
                if !fallback {
                    return Err(status.into());
                }
                tracing::debug!(
                    "GetCompactBlocksAtHeights unavailable ({}); falling back to N× GetBlock",
                    status.message()
                );
                let mut blocks = Vec::with_capacity(unique.len());
                for h in unique {
                    blocks.push(self.get_block(h).await?);
                }
                Ok(blocks)
            }
        }
    }

    /// Stream note commitments for building a local Merkle tree.
    pub async fn get_note_commitments(
        &mut self,
        start: u32,
        end: u32,
    ) -> Result<tonic::Streaming<proto::NoteCommitmentUpdate>, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let req = proto::BlockRange {
            start_height: start,
            end_height: end,
        };
        let response = client.get_note_commitments(req).await?;
        Ok(response.into_inner())
    }

    /// Stream nullifiers revealed in a block range.
    pub async fn get_nullifiers(
        &mut self,
        start: u32,
        end: u32,
    ) -> Result<tonic::Streaming<proto::NullifierUpdate>, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let req = proto::BlockRange {
            start_height: start,
            end_height: end,
        };
        let response = client.get_nullifiers(req).await?;
        Ok(response.into_inner())
    }

    /// Lookup ZKAS bincodes from the server.
    pub async fn lookup_zkas(
        &mut self,
        contract_id: &str,
    ) -> Result<proto::ZkasResponse, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let req = proto::ContractId {
            id: contract_id.to_string(),
        };
        let response = client.lookup_zkas(req).await?;
        Ok(response.into_inner())
    }

    /// Fetch OMR capabilities from the server.
    pub async fn get_omr_capabilities(&mut self) -> Result<proto::OmrCapabilities, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let response = client.get_omr_capabilities(proto::Empty {}).await?;
        Ok(response.into_inner())
    }

    /// UnifOMR Round 1: linear AHE partial-decrypt digest (ePrint 2026/910).
    ///
    /// Pass one or more detection keys (cap 16 on server). The first key is also
    /// sent in the primary `detection_key` field for older servers.
    pub async fn get_unif_omr_digest(
        &mut self,
        detection_keys: Vec<Vec<u8>>,
        start: u32,
        end: u32,
    ) -> Result<proto::OmrDigestResponse, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();

        let chunk_size = 1024 * 1024; // 1 MiB chunks
        let num_keys = detection_keys.len() as u32;

        let stream = async_stream::stream! {
            // First chunk MUST have header info
            yield proto::DetectionKeyChunk {
                start_height: start,
                end_height: end,
                num_keys,
                data: vec![],
                key_done: false,
            };

            for key in detection_keys {
                let mut offset = 0;
                while offset < key.len() {
                    let end_offset = std::cmp::min(offset + chunk_size, key.len());
                    let chunk_data = key[offset..end_offset].to_vec();
                    offset = end_offset;
                    let is_last = offset == key.len();

                    yield proto::DetectionKeyChunk {
                        start_height: 0,
                        end_height: 0,
                        num_keys: 0,
                        data: chunk_data,
                        key_done: is_last,
                    };
                }
                if key.is_empty() {
                     yield proto::DetectionKeyChunk {
                        start_height: 0,
                        end_height: 0,
                        num_keys: 0,
                        data: vec![],
                        key_done: true,
                    };
                }
            }
        };

        let response = client
            .get_unif_omr_digest(tonic::Request::new(stream))
            .await?;
        Ok(response.into_inner())
    }

    /// UnifOMR Round 2: batch PIR over compact-block limbs.
    pub async fn fetch_pir_batch(
        &mut self,
        query_ciphertexts: Vec<Vec<u8>>,
        start: u32,
        end: u32,
        limb_index: u32,
    ) -> Result<proto::BatchPirResponse, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let req = proto::BatchPirRequest {
            query_ciphertexts,
            start_height: start,
            end_height: end,
            limb_index,
        };
        let response = client.fetch_pir_batch(req).await?;
        Ok(response.into_inner())
    }

    /// Publish this wallet's UnifOMR clue public key for senders.
    ///
    /// `ownership_proof` is a Schnorr signature (darkfi-serial) over
    /// `b"DarkFi-UnifOMR-CluePK-v2" || network || key_version (u64 LE)`
    ///  || payment_pubkey || clue_public_key` under the payment
    /// [`darkfi_sdk::crypto::SecretKey`] (binds network + monotonic version
    /// against replay).
    pub async fn register_clue_public_key(
        &mut self,
        payment_pubkey: Vec<u8>,
        clue_public_key: Vec<u8>,
        ownership_proof: Vec<u8>,
        key_version: u64,
    ) -> Result<(), Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        client
            .register_clue_public_key(proto::CluePublicKeyRegistration {
                payment_pubkey,
                clue_public_key,
                ownership_proof,
                key_version,
            })
            .await?;
        Ok(())
    }

    /// Look up a recipient's UnifOMR clue public key.
    pub async fn get_clue_public_key(
        &mut self,
        payment_pubkey: Vec<u8>,
    ) -> Result<proto::CluePublicKey, Box<dyn Error>> {
        self.connect().await?;
        let mut client = self.client.clone().unwrap();
        let response = client
            .get_clue_public_key(proto::PaymentPubkey { payment_pubkey })
            .await?;
        Ok(response.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_is_exact_host_not_substring() {
        assert!(host_is_loopback("http://127.0.0.1:9067"));
        assert!(host_is_loopback("http://localhost:9067"));
        assert!(host_is_loopback("http://[::1]:9067"));
        assert!(!host_is_loopback("https://localhost.evil.com:443"));
        assert!(!host_is_loopback("https://lwd.example:9067"));
    }
}
