//! ICMP client for sending signals.

use std::net::IpAddr;
use std::time::Duration;

use crate::common::error::{GhostQueryError, Result};
use crate::common::types::IcmpSignal;
use crate::transport::icmp::IcmpPacket;

/// ICMP client for sending signals to the controller
pub struct IcmpClient {
    /// Target address
    target: IpAddr,
    /// Timeout for responses
    timeout: Duration,
}

impl IcmpClient {
    /// Create a new ICMP client
    pub fn new(target: IpAddr) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(5),
        }
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a signal
    pub async fn send_signal(&self, signal: IcmpSignal) -> Result<()> {
        let packet = IcmpPacket::new(signal);
        self.send_packet(&packet).await
    }

    /// Send a signal with session ID
    pub async fn send_signal_with_session(
        &self,
        signal: IcmpSignal,
        session_id: [u8; 8],
    ) -> Result<()> {
        let packet = IcmpPacket::new(signal).with_session(session_id);
        self.send_packet(&packet).await
    }

    /// Send a raw packet
    async fn send_packet(&self, packet: &IcmpPacket) -> Result<()> {
        // Note: Sending raw ICMP requires elevated privileges
        // This is a simplified implementation that would need
        // platform-specific code using pnet or similar

        let _payload = packet.to_bytes();

        #[cfg(target_os = "linux")]
        {
            self.send_linux_icmp(&_payload).await
        }

        #[cfg(target_os = "macos")]
        {
            self.send_macos_icmp(&_payload).await
        }

        #[cfg(target_os = "windows")]
        {
            self.send_windows_icmp(&_payload).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(GhostQueryError::IcmpError(
                "ICMP not supported on this platform".to_string(),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    async fn send_linux_icmp(&self, payload: &[u8]) -> Result<()> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::io::Write;

        // Create raw socket
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map_err(|e| GhostQueryError::IcmpError(format!("Socket creation failed: {}", e)))?;

        // Build ICMP echo request
        let mut icmp_packet = vec![
            8, // Type: Echo Request
            0, // Code
            0, 0, // Checksum (calculated below)
            0, 0, // Identifier
            0, 1, // Sequence number
        ];
        icmp_packet.extend_from_slice(payload);

        // Calculate checksum
        let checksum = Self::calculate_checksum(&icmp_packet);
        icmp_packet[2] = (checksum >> 8) as u8;
        icmp_packet[3] = (checksum & 0xFF) as u8;

        // Send
        let dest: std::net::SocketAddr = match self.target {
            IpAddr::V4(v4) => std::net::SocketAddr::new(IpAddr::V4(v4), 0),
            IpAddr::V6(_) => {
                return Err(GhostQueryError::IcmpError("IPv6 not supported".to_string()))
            }
        };

        socket
            .send_to(&icmp_packet, &dest.into())
            .map_err(|e| GhostQueryError::IcmpError(format!("Send failed: {}", e)))?;

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn send_macos_icmp(&self, payload: &[u8]) -> Result<()> {
        // macOS implementation similar to Linux but may need SOCK_DGRAM
        use socket2::{Domain, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)
            .map_err(|e| GhostQueryError::IcmpError(format!("Socket creation failed: {}", e)))?;

        // Build ICMP packet
        let mut icmp_packet = vec![8, 0, 0, 0, 0, 0, 0, 1];
        icmp_packet.extend_from_slice(payload);

        let checksum = Self::calculate_checksum(&icmp_packet);
        icmp_packet[2] = (checksum >> 8) as u8;
        icmp_packet[3] = (checksum & 0xFF) as u8;

        let dest: std::net::SocketAddr = match self.target {
            IpAddr::V4(v4) => std::net::SocketAddr::new(IpAddr::V4(v4), 0),
            IpAddr::V6(_) => {
                return Err(GhostQueryError::IcmpError("IPv6 not supported".to_string()))
            }
        };

        socket
            .send_to(&icmp_packet, &dest.into())
            .map_err(|e| GhostQueryError::IcmpError(format!("Send failed: {}", e)))?;

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn send_windows_icmp(&self, payload: &[u8]) -> Result<()> {
        // Windows requires IcmpSendEcho or similar API
        // This is a placeholder
        Err(GhostQueryError::IcmpError(
            "Windows ICMP requires IcmpSendEcho API".to_string(),
        ))
    }

    /// Calculate ICMP checksum
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Sum up 16-bit words
        for chunk in data.chunks(2) {
            let word = if chunk.len() == 2 {
                ((chunk[0] as u16) << 8) | (chunk[1] as u16)
            } else {
                (chunk[0] as u16) << 8
            };
            sum = sum.wrapping_add(word as u32);
        }

        // Add carry
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        !sum as u16
    }

    /// Open transmission window
    pub async fn open_window(&self, session_id: [u8; 8]) -> Result<()> {
        self.send_signal_with_session(IcmpSignal::WindowOpen, session_id)
            .await
    }

    /// Close transmission window
    pub async fn close_window(&self, session_id: [u8; 8]) -> Result<()> {
        self.send_signal_with_session(IcmpSignal::WindowClose, session_id)
            .await
    }

    /// Signal session start
    pub async fn session_init(&self, session_id: [u8; 8]) -> Result<()> {
        self.send_signal_with_session(IcmpSignal::SessionInit, session_id)
            .await
    }

    /// Signal session end
    pub async fn session_end(&self, session_id: [u8; 8]) -> Result<()> {
        self.send_signal_with_session(IcmpSignal::SessionEnd, session_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_checksum() {
        // Test with known data
        let data = vec![8, 0, 0, 0, 0, 1, 0, 1];
        let checksum = IcmpClient::calculate_checksum(&data);
        assert!(checksum != 0);
    }

    #[test]
    fn test_client_creation() {
        let client = IcmpClient::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(client.target, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }
}

