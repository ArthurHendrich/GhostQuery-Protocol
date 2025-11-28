//! ICMP server for receiving signals.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::common::error::{GhostQueryError, Result};
use crate::common::types::IcmpSignal;
use crate::transport::icmp::IcmpPacket;

/// Handler for received ICMP signals
#[async_trait]
pub trait SignalHandler: Send + Sync {
    /// Handle a received signal
    async fn handle_signal(&self, signal: IcmpSignal, session_id: Option<[u8; 8]>);
}

/// ICMP server for receiving control signals
pub struct IcmpServer {
    /// Whether the server is running
    running: Arc<RwLock<bool>>,
    /// Channel for received signals
    signal_tx: Option<mpsc::Sender<IcmpPacket>>,
}

impl IcmpServer {
    /// Create a new ICMP server
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            signal_tx: None,
        }
    }

    /// Start the server with a handler
    pub async fn start<H: SignalHandler + 'static>(
        &mut self,
        handler: Arc<H>,
    ) -> Result<()> {
        let (tx, mut rx) = mpsc::channel::<IcmpPacket>(100);
        self.signal_tx = Some(tx.clone());
        *self.running.write() = true;

        // Spawn handler task
        let handler_clone = Arc::clone(&handler);
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                handler_clone
                    .handle_signal(packet.signal, packet.session_id)
                    .await;
            }
        });

        // Start listening
        self.listen().await
    }

    /// Listen for ICMP packets
    async fn listen(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.listen_linux().await
        }

        #[cfg(target_os = "macos")]
        {
            self.listen_macos().await
        }

        #[cfg(target_os = "windows")]
        {
            Err(GhostQueryError::IcmpError(
                "Windows ICMP server not implemented".to_string(),
            ))
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(GhostQueryError::IcmpError(
                "ICMP not supported on this platform".to_string(),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    async fn listen_linux(&self) -> Result<()> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::io::Read;

        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map_err(|e| GhostQueryError::IcmpError(format!("Socket creation failed: {}", e)))?;

        let mut buf = [0u8; 1500];

        while *self.running.read() {
            // This is blocking - in production, use async I/O
            match socket.recv(&mut buf) {
                Ok(len) if len > 28 => {
                    // Skip IP header (20 bytes) and ICMP header (8 bytes)
                    let payload = &buf[28..len];

                    if let Some(packet) = IcmpPacket::from_bytes(payload) {
                        if let Some(tx) = &self.signal_tx {
                            let _ = tx.try_send(packet);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn listen_macos(&self) -> Result<()> {
        // macOS implementation
        use socket2::{Domain, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)
            .map_err(|e| GhostQueryError::IcmpError(format!("Socket creation failed: {}", e)))?;

        let mut buf = [0u8; 1500];

        while *self.running.read() {
            let mut recv_buf = [std::mem::MaybeUninit::new(0u8); 1500];
            match socket.recv(&mut recv_buf) {
                Ok(len) if len > 8 => {
                    // Copy to initialized buffer
                    for i in 0..len.min(1500) {
                        buf[i] = unsafe { recv_buf[i].assume_init() };
                    }
                    let payload = &buf[8..len];

                    if let Some(packet) = IcmpPacket::from_bytes(payload) {
                        if let Some(tx) = &self.signal_tx {
                            let _ = tx.try_send(packet);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Stop the server
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }
}

impl Default for IcmpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple signal handler that stores received signals
pub struct SimpleSignalHandler {
    signals: RwLock<Vec<(IcmpSignal, Option<[u8; 8]>)>>,
}

impl SimpleSignalHandler {
    pub fn new() -> Self {
        Self {
            signals: RwLock::new(Vec::new()),
        }
    }

    pub fn get_signals(&self) -> Vec<(IcmpSignal, Option<[u8; 8]>)> {
        self.signals.read().clone()
    }

    pub fn clear(&self) {
        self.signals.write().clear();
    }
}

impl Default for SimpleSignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignalHandler for SimpleSignalHandler {
    async fn handle_signal(&self, signal: IcmpSignal, session_id: Option<[u8; 8]>) {
        self.signals.write().push((signal, session_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_handler() {
        let handler = SimpleSignalHandler::new();
        let session_id = [0x01; 8];

        handler
            .handle_signal(IcmpSignal::WindowOpen, Some(session_id))
            .await;

        let signals = handler.get_signals();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].0, IcmpSignal::WindowOpen);
    }
}

