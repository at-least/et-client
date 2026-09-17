//! Per-direction symmetric crypto, byte-exact with upstream `CryptoHandler`
//! (libsodium `crypto_secretbox_easy` = XSalsa20-Poly1305).
//!
//! Semantics fixed by the C++ implementation:
//! - the 24-byte nonce starts as all-zero except the **last** byte, which is
//!   the direction MSB (`0` client→server, `1` server→client);
//! - the nonce is incremented **before** every encrypt and every decrypt,
//!   little-endian across all 24 bytes (`incrementNonce` in
//!   `CryptoHandler.cpp` increments byte 0 first and carries upward);
//! - the nonce counter is *per handler instance* and therefore survives
//!   reconnects — never recreate the handler on a new socket.

use crypto_secretbox::aead::{Aead, KeyInit, Payload};
use crypto_secretbox::{aead::generic_array::GenericArray, XSalsa20Poly1305};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const MAC_BYTES: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {KEY_BYTES} bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("ciphertext too short to contain the MAC: {0} bytes")]
    CiphertextTooShort(usize),
    #[error("decryption failed (key mismatch or corrupted packet)")]
    DecryptFailed,
}

pub struct CryptoHandler {
    cipher: XSalsa20Poly1305,
    nonce: [u8; NONCE_BYTES],
}

impl CryptoHandler {
    /// Mirrors `CryptoHandler::CryptoHandler(key, nonceMSB)`.
    pub fn new(key: &[u8; KEY_BYTES], nonce_msb: u8) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[NONCE_BYTES - 1] = nonce_msb;
        Self {
            cipher: XSalsa20Poly1305::new(GenericArray::from_slice(key)),
            nonce,
        }
    }

    /// Port of `incrementNonce`: little-endian increment across the whole
    /// 24-byte nonce.
    fn increment_nonce(&mut self) {
        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    /// `CryptoHandler::encrypt`: increments the nonce, then appends the
    /// 16-byte MAC (`crypto_secretbox_easy` layout).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.increment_nonce();
        let nonce = GenericArray::from_slice(&self.nonce);
        self.cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &[] })
            .expect("XSalsa20-Poly1305 encryption cannot fail")
    }

    /// `CryptoHandler::decrypt`: increments the nonce, then verifies the MAC
    /// and recovers the plaintext.
    ///
    /// Divergence (safety, not wire behavior): a ciphertext shorter than the
    /// MAC is rejected *before* the nonce advances. Upstream C++ computes
    /// `length - MACBYTES` on unsigned types and aborts the process in that
    /// case, so there is no upstream nonce behavior to match.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < MAC_BYTES {
            return Err(CryptoError::CiphertextTooShort(ciphertext.len()));
        }
        self.increment_nonce();
        let nonce = GenericArray::from_slice(&self.nonce);
        self.cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: &[] })
            .map_err(|_| CryptoError::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CLIENT_SERVER_NONCE_MSB, SERVER_CLIENT_NONCE_MSB};

    fn key(seed: u8) -> [u8; KEY_BYTES] {
        [seed; KEY_BYTES]
    }

    #[test]
    fn round_trip_and_nonce_advance() {
        // One handler per direction *endpoint*: the sender's counter and the
        // receiver's counter advance in lockstep (upstream constructs
        // separate CryptoHandlers for reading and writing).
        let mut sender = CryptoHandler::new(&key(1), CLIENT_SERVER_NONCE_MSB);
        let mut receiver = CryptoHandler::new(&key(1), CLIENT_SERVER_NONCE_MSB);
        let msg = b"hello terminal";
        let c1 = sender.encrypt(msg);
        let c2 = sender.encrypt(msg);
        // Distinct nonces must produce distinct ciphertexts for the same
        // plaintext (this is what makes replay impossible without tracking).
        assert_ne!(c1, c2);
        assert_eq!(c1.len(), msg.len() + MAC_BYTES);
        assert_eq!(receiver.decrypt(&c1).unwrap(), msg);
        assert_eq!(receiver.decrypt(&c2).unwrap(), msg);
    }

    #[test]
    fn directions_are_independent_streams() {
        // The two directions run separate counters, each with its own MSB.
        // The server's reader uses the client's writer MSB (both track the
        // client→server stream).
        let mut client_writer = CryptoHandler::new(&key(2), CLIENT_SERVER_NONCE_MSB);
        let mut server_reader = CryptoHandler::new(&key(2), CLIENT_SERVER_NONCE_MSB);
        let c = client_writer.encrypt(b"x");
        assert_eq!(server_reader.decrypt(&c).unwrap(), b"x");
        // Same plaintext, opposite direction MSB → different first nonce.
        let mut server_writer = CryptoHandler::new(&key(2), SERVER_CLIENT_NONCE_MSB);
        assert_ne!(server_writer.encrypt(b"x"), c);
    }

    #[test]
    fn wrong_key_and_tamper_fail() {
        let mut a = CryptoHandler::new(&key(3), 0);
        let mut b = CryptoHandler::new(&key(4), 0);
        let c = a.encrypt(b"secret");
        assert!(matches!(b.decrypt(&c), Err(CryptoError::DecryptFailed)));
        let mut tampered = c.clone();
        tampered[0] ^= 1;
        assert!(matches!(a.decrypt(&tampered), Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn short_ciphertext_rejected_without_touching_nonce() {
        let mut sender = CryptoHandler::new(&key(5), 0);
        let mut receiver = CryptoHandler::new(&key(5), 0);
        assert!(matches!(
            receiver.decrypt(&[0u8; 10]),
            Err(CryptoError::CiphertextTooShort(10))
        ));
        // The nonce must not have advanced for the rejected input; a
        // subsequent decrypt of a real packet still works.
        let c = sender.encrypt(b"still aligned");
        assert_eq!(receiver.decrypt(&c).unwrap(), b"still aligned");
    }

    #[test]
    fn nonce_carries_across_all_24_bytes() {
        // Increment byte-by-byte through a controlled sequence: starting
        // nonce = [0xff, 0x00..] must roll into [0x00, 0x01, 0x00..].
        let mut handler = CryptoHandler::new(&key(6), 0);
        handler.nonce[0] = 0xff;
        handler.increment_nonce();
        assert_eq!(handler.nonce[0], 0x00);
        assert_eq!(handler.nonce[1], 0x01);
        for b in handler.nonce.iter().skip(2) {
            assert_eq!(*b, 0);
        }
    }
}
