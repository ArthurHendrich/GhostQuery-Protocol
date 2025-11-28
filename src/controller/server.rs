//! Controller server implementation.
//!
//! Runs the authoritative DNS server and manages sessions.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::common::constants::DNS_SERVER_PORT;
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{ChunkId, FileHash, SessionId, SessionMetadata};
use crate::controller::shadow::{ChunkReceiveResult, ShadowMemory, ShadowStats};
use crate::crypto::keys::KeyManager;
use crate::transport::dns::query::ParsedQuery;
use crate::transport::dns::response::DnsResponse;
use crate::transport::dns::server::{DnsServerConfig, QueryHandler};

/// Configuration for the controller server
#[derive(Debug, Clone)]
pub struct ControllerConfig {
    /// Bind address for DNS server
    pub bind_addr: SocketAddr,
    /// Domain this server is authoritative for
    pub domain: String,
    /// Master key for decryption
    pub master_key: [u8; 32],
    /// Output directory for completed files
    pub output_dir: Option<std::path::PathBuf>,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], DNS_SERVER_PORT)),
            domain: "ghost.local".to_string(),
            master_key: [0u8; 32],
            output_dir: None,
        }
    }
}

/// The controller server
pub struct ControllerServer {
    /// Configuration
    config: ControllerConfig,
    /// Shadow memory for file reconstruction
    shadow: Arc<ShadowMemory>,
    /// Key manager
    keys: KeyManager,
    /// Whether server is running
    running: Arc<RwLock<bool>>,
    /// Pending session initializations
    pending_inits: Arc<RwLock<std::collections::HashMap<SessionId, PendingInit>>>,
}

/// Pending session initialization
#[derive(Debug, Clone)]
struct PendingInit {
    file_hash: FileHash,
    total_chunks: Option<u32>,
}

impl ControllerServer {
    /// Create a new controller server
    pub fn new(config: ControllerConfig) -> Self {
        let keys = KeyManager::from_key(config.master_key);
        let shadow = if let Some(ref output_dir) = config.output_dir {
            ShadowMemory::new(keys.clone()).with_output_dir(output_dir)
        } else {
            ShadowMemory::new(keys.clone())
        };

        Self {
            config,
            shadow: Arc::new(shadow),
            keys,
            running: Arc::new(RwLock::new(false)),
            pending_inits: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Get shadow memory reference
    pub fn shadow(&self) -> Arc<ShadowMemory> {
        Arc::clone(&self.shadow)
    }

    /// Get active sessions
    pub fn active_sessions(&self) -> Vec<SessionId> {
        self.shadow.active_sessions()
    }

    /// Get session stats
    pub fn session_stats(&self, session_id: &SessionId) -> Option<ShadowStats> {
        self.shadow.session_stats(session_id)
    }

    /// Get all session stats
    pub fn all_stats(&self) -> Vec<ShadowStats> {
        self.active_sessions()
            .iter()
            .filter_map(|id| self.shadow.session_stats(id))
            .collect()
    }

    /// Create the query handler
    pub fn create_handler(self: &Arc<Self>) -> Arc<ControllerHandler> {
        Arc::new(ControllerHandler {
            server: Arc::clone(self),
        })
    }

    /// Start the server
    pub async fn start(self: Arc<Self>) -> Result<()> {
        let dns_config = DnsServerConfig {
            bind_addr: self.config.bind_addr,
            domain: self.config.domain.clone(),
            ..Default::default()
        };

        let handler = self.create_handler();
        let dns_server = crate::transport::dns::server::DnsServer::new(dns_config);

        *self.running.write() = true;

        tracing::info!("Controller started on {}", self.config.bind_addr);
        tracing::info!("Authoritative for domain: {}", self.config.domain);

        dns_server.start(handler).await
    }

    /// Stop the server
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Handle session initialization
    fn handle_init(&self, session_id: SessionId, file_hash_hex: &str) -> DnsResponse {
        match FileHash::from_hex(file_hash_hex) {
            Ok(file_hash) => {
                // Store pending init
                self.pending_inits.write().insert(
                    session_id,
                    PendingInit {
                        file_hash,
                        total_chunks: None,
                    },
                );

                tracing::info!("Session {} initialized", session_id);
                DnsResponse::ack()
            }
            Err(_) => {
                tracing::warn!("Invalid file hash in init: {}", file_hash_hex);
                DnsResponse::nxdomain()
            }
        }
    }

    /// Handle session completion
    fn handle_done(&self, session_id: SessionId) -> DnsResponse {
        if self.shadow.is_session_complete(&session_id) {
            // Save file if output dir is configured
            if let Some(ref output_dir) = self.config.output_dir {
                let output_path = output_dir.join(format!("{}.bin", session_id));
                if let Err(e) = self.shadow.save_session(&session_id, &output_path) {
                    tracing::error!("Failed to save session {}: {}", session_id, e);
                } else {
                    tracing::info!("Session {} saved to {:?}", session_id, output_path);
                }
            }

            DnsResponse::complete()
        } else {
            // Session not complete, return missing chunks
            let stats = self.shadow.session_stats(&session_id);
            tracing::warn!(
                "Session {} completion requested but only {:.1}% complete",
                session_id,
                stats.map(|s| s.completion_pct).unwrap_or(0.0)
            );

            DnsResponse::nxdomain()
        }
    }

    /// Handle a data chunk
    fn handle_chunk(
        &self,
        session_id: SessionId,
        sequence: u32,
        payload: &str,
    ) -> DnsResponse {
        // Check if we need to initialize the session
        if !self.shadow.active_sessions().contains(&session_id) {
            if let Some(pending) = self.pending_inits.write().remove(&session_id) {
                // Initialize session with estimated total chunks
                // In practice, the first chunk might contain this info
                let estimated_chunks = 1000; // Will be updated as chunks arrive

                let metadata = SessionMetadata::new(
                    session_id,
                    pending.file_hash,
                    estimated_chunks,
                    32, // Default chunk size
                    estimated_chunks as u64 * 32,
                );

                if let Err(e) = self.shadow.init_session(metadata) {
                    tracing::error!("Failed to init session {}: {}", session_id, e);
                    return DnsResponse::nxdomain();
                }
            } else {
                // Unknown session
                tracing::warn!("Chunk for unknown session: {}", session_id);
                return DnsResponse::nxdomain();
            }
        }

        // Receive the chunk
        match self.shadow.receive_chunk(session_id, sequence, payload) {
            Ok(ChunkReceiveResult::Ack) => {
                tracing::debug!("Session {} chunk {} acked", session_id, sequence);
                DnsResponse::ack()
            }
            Ok(ChunkReceiveResult::Retransmit(missing)) => {
                if let Some(first_missing) = missing.first() {
                    tracing::debug!(
                        "Session {} requesting retransmit of chunk {}",
                        session_id,
                        first_missing.as_u32()
                    );
                    DnsResponse::retransmit(*first_missing)
                } else {
                    DnsResponse::ack()
                }
            }
            Ok(ChunkReceiveResult::Complete) => {
                tracing::info!("Session {} all chunks received", session_id);
                DnsResponse::complete()
            }
            Err(e) => {
                tracing::error!("Error receiving chunk: {}", e);
                DnsResponse::nxdomain()
            }
        }
    }
}

/// Query handler for the controller
pub struct ControllerHandler {
    server: Arc<ControllerServer>,
}

#[async_trait]
impl QueryHandler for ControllerHandler {
    async fn handle_query(&self, query: &ParsedQuery) -> DnsResponse {
        if query.is_init {
            self.server.handle_init(query.session_id, &query.payload)
        } else if query.is_done {
            self.server.handle_done(query.session_id)
        } else {
            self.server
                .handle_chunk(query.session_id, query.sequence, &query.payload)
        }
    }

    async fn handle_init(&self, session_id: SessionId, file_hash: &str) -> DnsResponse {
        self.server.handle_init(session_id, file_hash)
    }

    async fn handle_done(&self, session_id: SessionId) -> DnsResponse {
        self.server.handle_done(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ControllerConfig::default();
        assert_eq!(config.bind_addr.port(), DNS_SERVER_PORT);
    }

    #[test]
    fn test_server_creation() {
        let config = ControllerConfig::default();
        let server = ControllerServer::new(config);

        assert!(server.active_sessions().is_empty());
    }

    #[test]
    fn test_handle_init() {
        let config = ControllerConfig::default();
        let server = ControllerServer::new(config);

        let session_id = SessionId::new();
        let file_hash = "0".repeat(64); // 32 bytes in hex

        let response = server.handle_init(session_id, &file_hash);
        assert!(response.is_ack());
    }
}

