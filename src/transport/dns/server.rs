//! DNS server for the controller (authoritative server).

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::net::UdpSocket;

use crate::common::constants::{DEFAULT_TTL, DNS_SERVER_PORT};
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{ChunkId, SessionId};
use crate::transport::dns::query::ParsedQuery;
use crate::transport::dns::response::DnsResponse;

/// Handler trait for processing DNS queries
#[async_trait]
pub trait QueryHandler: Send + Sync {
    /// Handle a parsed query and return a response
    async fn handle_query(&self, query: &ParsedQuery) -> DnsResponse;

    /// Handle session initialization
    async fn handle_init(&self, session_id: SessionId, file_hash: &str) -> DnsResponse;

    /// Handle session completion
    async fn handle_done(&self, session_id: SessionId) -> DnsResponse;
}

/// DNS server configuration
#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    /// Bind address
    pub bind_addr: SocketAddr,
    /// Domain this server is authoritative for
    pub domain: String,
    /// Default TTL for responses
    pub default_ttl: u32,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], DNS_SERVER_PORT)),
            domain: "ghost.local".to_string(),
            default_ttl: DEFAULT_TTL,
        }
    }
}

/// Simple DNS server for the controller
pub struct DnsServer {
    config: DnsServerConfig,
    running: Arc<RwLock<bool>>,
}

impl DnsServer {
    /// Create a new DNS server
    pub fn new(config: DnsServerConfig) -> Self {
        Self {
            config,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the server with the given handler
    pub async fn start<H: QueryHandler + 'static>(
        &self,
        handler: Arc<H>,
    ) -> Result<()> {
        let socket = UdpSocket::bind(self.config.bind_addr)
            .await
            .map_err(|e| GhostQueryError::InternalError(format!("Failed to bind: {}", e)))?;

        *self.running.write() = true;

        tracing::info!("DNS server started on {}", self.config.bind_addr);

        let mut buf = [0u8; 512]; // Standard DNS UDP size

        while *self.running.read() {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let data = buf[..len].to_vec();
                    let socket_clone = socket.local_addr().ok();
                    let handler_clone = Arc::clone(&handler);
                    let domain = self.config.domain.clone();

                    // Handle in a separate task
                    tokio::spawn(async move {
                        if let Some(_local) = socket_clone {
                            if let Err(e) =
                                Self::handle_packet(&data, addr, &domain, handler_clone).await
                            {
                                tracing::warn!("Error handling DNS packet: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Error receiving DNS packet: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Stop the server
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Handle a DNS packet
    async fn handle_packet<H: QueryHandler>(
        _data: &[u8],
        _addr: SocketAddr,
        _domain: &str,
        _handler: Arc<H>,
    ) -> Result<()> {
        // This is a simplified implementation
        // A full implementation would parse the DNS packet, extract the query,
        // call the handler, and send back a proper DNS response

        // For now, we'll use this as a placeholder
        // The actual DNS parsing would use trust-dns-proto

        Ok(())
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }
}

/// Simple in-memory handler for testing
pub struct SimpleHandler {
    /// Acknowledged chunks per session
    acked: RwLock<std::collections::HashMap<SessionId, std::collections::HashSet<u32>>>,
}

impl SimpleHandler {
    pub fn new() -> Self {
        Self {
            acked: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn get_acked(&self, session_id: &SessionId) -> Vec<u32> {
        self.acked
            .read()
            .get(session_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }
}

impl Default for SimpleHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl QueryHandler for SimpleHandler {
    async fn handle_query(&self, query: &ParsedQuery) -> DnsResponse {
        // Record the chunk as received
        let mut acked = self.acked.write();
        acked
            .entry(query.session_id)
            .or_insert_with(std::collections::HashSet::new)
            .insert(query.sequence);

        // Return ACK
        DnsResponse::ack()
    }

    async fn handle_init(&self, session_id: SessionId, _file_hash: &str) -> DnsResponse {
        // Initialize session tracking
        let mut acked = self.acked.write();
        acked.insert(session_id, std::collections::HashSet::new());

        DnsResponse::ack()
    }

    async fn handle_done(&self, _session_id: SessionId) -> DnsResponse {
        DnsResponse::complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = DnsServerConfig::default();
        assert_eq!(config.bind_addr.port(), DNS_SERVER_PORT);
    }

    #[tokio::test]
    async fn test_simple_handler() {
        let handler = SimpleHandler::new();
        let session_id = SessionId::new();

        let query = ParsedQuery {
            payload: "test".to_string(),
            sequence: 0,
            session_id,
            is_init: false,
            is_done: false,
        };

        let response = handler.handle_query(&query).await;
        assert!(response.is_ack());

        let acked = handler.get_acked(&session_id);
        assert_eq!(acked, vec![0]);
    }
}

