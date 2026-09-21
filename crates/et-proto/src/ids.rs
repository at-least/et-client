//! Client id / passkey generation — port of upstream `genRandomAlphaNum`
//! (`Headers.hpp`) and the `XXX` convention from `SshSetupHandler.cpp`.

/// Length of the client id.
pub const ID_LEN: usize = 16;
/// Length of the passkey (also the `crypto_secretbox` key length in bytes).
pub const PASSKEY_LEN: usize = 32;

/// `genRandomAlphaNum(len)` alphabet.
const ALPHANUM: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Uniformly samples `len` alphanumeric characters (rejection sampling;
/// 256 % 62 = 8 rejected values per byte).
pub fn random_alphanum(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        getrandom::fill(&mut buf).expect("system randomness unavailable");
        for &b in buf.iter() {
            if (b as usize) < ALPHANUM.len() {
                out.push(ALPHANUM[b as usize]);
                if out.len() == len {
                    break;
                }
            }
        }
    }
    out
}

/// `(id, passkey)` as a fresh client sends them over SSH: the id starts
/// with `XXX` so a modern server regenerates both.
pub fn generate_id_passkey() -> (String, String) {
    let mut id = random_alphanum(ID_LEN);
    id[0] = b'X';
    id[1] = b'X';
    id[2] = b'X';
    (
        String::from_utf8(id).expect("alphanumeric is utf-8"),
        String::from_utf8(random_alphanum(PASSKEY_LEN)).expect("alphanumeric is utf-8"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_and_charset() {
        for _ in 0..64 {
            let (id, passkey) = generate_id_passkey();
            assert_eq!(id.len(), ID_LEN);
            assert_eq!(&id[..3], "XXX");
            assert_eq!(passkey.len(), PASSKEY_LEN);
            assert!(id
                .bytes()
                .chain(passkey.bytes())
                .all(|b| ALPHANUM.contains(&b)));
        }
    }
}
