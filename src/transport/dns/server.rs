//! DNS server for the controller (authoritative server).

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::rdata::A;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::common::constants::{DEFAULT_TTL, DNS_SERVER_PORT};
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::SessionId;
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
        let socket = Arc::new(
            UdpSocket::bind(self.config.bind_addr)
                .await
                .map_err(|e| GhostQueryError::InternalError(format!("Failed to bind: {}", e)))?,
        );

        *self.running.write() = true;

        tracing::info!("DNS server started on {}", self.config.bind_addr);

        let mut buf = [0u8; 512];

        while *self.running.read() {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let data = buf[..len].to_vec();
                    let socket_clone = Arc::clone(&socket);
                    let handler_clone = Arc::clone(&handler);
                    let domain = self.config.domain.clone();
                    let ttl = self.config.default_ttl;

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_packet(&data, addr, &domain, ttl, handler_clone, socket_clone).await
                        {
                            tracing::warn!("Error handling DNS packet: {}", e);
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
        data: &[u8],
        addr: SocketAddr,
        domain: &str,
        ttl: u32,
        handler: Arc<H>,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        // Parse incoming DNS message
        let request = Message::from_bytes(data)
            .map_err(|e| GhostQueryError::DnsParseError(e.to_string()))?;

        let request_id = request.id();
        
        // Get the query
        let query = request.queries().first().ok_or_else(|| {
            GhostQueryError::DnsParseError("No query in request".to_string())
        })?;

        let qname_raw = query.name().to_string();
        // Remove trailing dot if present (DNS FQDN format)
        let qname = qname_raw.trim_end_matches('.');
        tracing::debug!("Received query for: {} (raw: {})", qname, qname_raw);

        // Parse the query
        let parsed = match ParsedQuery::parse(qname, domain) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to parse query {}: {}", qname, e);
                // Send NXDOMAIN for unparseable queries
                let response = Self::build_nxdomain_response(request_id, &qname);
                Self::send_response(&socket, addr, &response).await?;
                return Ok(());
            }
        };

        // Handle the query
        let dns_response = if parsed.is_init {
            tracing::info!("Session init: {}", parsed.session_id);
            handler.handle_init(parsed.session_id, &parsed.payload).await
        } else if parsed.is_done {
            tracing::info!("Session done: {}", parsed.session_id);
            handler.handle_done(parsed.session_id).await
        } else {
            tracing::info!("Chunk seq={} session={} payload_len={}", parsed.sequence, parsed.session_id, parsed.payload.len());
            handler.handle_query(&parsed).await
        };

        // Build DNS response
        let response_bytes = Self::build_response(request_id, &qname, &dns_response, ttl)?;
        
        // Send response
        Self::send_response(&socket, addr, &response_bytes).await?;

        Ok(())
    }

    /// Build a DNS response message
    fn build_response(
        request_id: u16,
        qname: &str,
        dns_response: &DnsResponse,
        ttl: u32,
    ) -> Result<Vec<u8>> {
        let mut message = Message::new();
        
        // Set header
        let mut header = Header::new();
        header.set_id(request_id);
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_authoritative(true);
        header.set_response_code(ResponseCode::NoError);
        message.set_header(header);

        // Add query section
        let name = Name::from_ascii(qname)
            .map_err(|e| GhostQueryError::DnsParseError(e.to_string()))?;

        // Add answer with command IP
        if let Some(ip) = dns_response.a_record {
            let mut record = Record::new();
            record.set_name(name);
            record.set_record_type(RecordType::A);
            record.set_ttl(ttl);
            record.set_data(Some(RData::A(A(ip))));
            message.add_answer(record);
        }

        message.to_bytes()
            .map_err(|e| GhostQueryError::DnsParseError(e.to_string()))
    }

    /// Build NXDOMAIN response
    fn build_nxdomain_response(request_id: u16, _qname: &str) -> Vec<u8> {
        let mut message = Message::new();
        
        let mut header = Header::new();
        header.set_id(request_id);
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_authoritative(true);
        header.set_response_code(ResponseCode::NXDomain);
        message.set_header(header);

        message.to_bytes().unwrap_or_default()
    }

    /// Send response to client
    async fn send_response(
        socket: &UdpSocket,
        addr: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        socket
            .send_to(data, addr)
            .await
            .map_err(|e| GhostQueryError::InternalError(format!("Failed to send: {}", e)))?;
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
        let mut acked = self.acked.write();
        acked
            .entry(query.session_id)
            .or_insert_with(std::collections::HashSet::new)
            .insert(query.sequence);

        DnsResponse::ack()
    }

    async fn handle_init(&self, session_id: SessionId, _file_hash: &str) -> DnsResponse {
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
