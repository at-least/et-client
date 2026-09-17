//! The protocol packet, byte-exact with upstream `Packet.hpp`.
//!
//! Wire layout: `[encrypted: u8 as 0/1][header: u8][payload]`. The payload of
//! an encrypted packet is `ciphertext = plaintext || 16-byte MAC`
//! (`crypto_secretbox_easy` layout). Encryption happens exactly once, when
//! the packet enters a `BackedWriter`; the backup buffer stores the
//! serialized *ciphertext* so reconnect catch-up resends identical bytes
//! without re-encrypting (re-encrypting would advance the nonce stream and
//! desynchronize both sides).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    encrypted: bool,
    header: u8,
    payload: Vec<u8>,
}

impl Packet {
    pub const HEADER_SIZE: usize = 2;

    /// `Packet(header, payload)` — a decrypted, unencrypted packet.
    pub fn new(header: u8, payload: Vec<u8>) -> Self {
        Self { encrypted: false, header, payload }
    }

    /// `Packet::deserialize(serializedPacket)`.
    ///
    /// Returns `None` for empty input (upstream reads `[0]`/`[1]` and would
    /// UB; the frame layer above guarantees ≥ 2 bytes, this is defense in
    /// depth).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let (&flags, rest) = bytes.split_first()?;
        let (&header, payload) = rest.split_first()?;
        Some(Self { encrypted: flags != 0, header, payload: payload.to_vec() })
    }

    /// `Packet::serialize`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_SIZE + self.payload.len());
        out.push(self.encrypted as u8);
        out.push(self.header);
        out.extend_from_slice(&self.payload);
        out
    }

    /// `Packet::encrypt` — encrypts the payload in place. Calling this on an
    /// already-encrypted packet is the "already encrypted" `STFATAL` path
    /// upstream; it is a bug in the caller, so it panics.
    pub fn encrypt(&mut self, crypto: &mut crate::CryptoHandler) {
        assert!(!self.encrypted, "tried to encrypt a packet that was already encrypted");
        self.payload = crypto.encrypt(&self.payload);
        self.encrypted = true;
    }

    /// `Packet::decrypt` — decrypts the payload in place.
    pub fn decrypt(&mut self, crypto: &mut crate::CryptoHandler) -> Result<(), crate::crypto::CryptoError> {
        assert!(self.encrypted, "tried to decrypt a packet that wasn't encrypted");
        self.payload = crypto.decrypt(&self.payload)?;
        self.encrypted = false;
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn header(&self) -> u8 {
        self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_matches_upstream_layout() {
        let p = Packet::new(0xfe, b"abc".to_vec());
        assert_eq!(p.serialize(), vec![0u8, 0xfe, b'a', b'b', b'c']);
        let parsed = Packet::parse(&p.serialize()).unwrap();
        assert_eq!(parsed, p);
        assert!(!parsed.is_encrypted());
    }

    #[test]
    fn empty_payload_round_trip() {
        let p = Packet::new(crate::terminal_packet_type::KEEP_ALIVE, Vec::new());
        assert_eq!(Packet::parse(&p.serialize()).unwrap(), p);
    }

    #[test]
    fn encrypted_round_trip_through_backup_storage() {
        // Models the reconnect path: serialize-encrypt-once, store the
        // ciphertext bytes, decrypt later — the catch-up buffer carries
        // serialized packets whose payload is still ciphertext.
        let mut sender = crate::CryptoHandler::new(&[7u8; 32], crate::CLIENT_SERVER_NONCE_MSB);
        let mut receiver = crate::CryptoHandler::new(&[7u8; 32], crate::CLIENT_SERVER_NONCE_MSB);
        let mut p = Packet::new(crate::terminal_packet_type::TERMINAL_BUFFER, b"data".to_vec());
        p.encrypt(&mut sender);
        assert!(p.is_encrypted());
        let stored = p.serialize();

        let mut from_wire = Packet::parse(&stored).unwrap();
        assert!(from_wire.is_encrypted());
        from_wire.decrypt(&mut receiver).unwrap();
        assert_eq!(from_wire.payload(), b"data");
    }

    #[test]
    fn parse_rejects_truncated_input() {
        assert!(Packet::parse(&[]).is_none());
        assert!(Packet::parse(&[1u8]).is_none());
    }
}
