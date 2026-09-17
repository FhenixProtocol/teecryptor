//! The on-chain handle's metadata byte layout, mirroring cofhe's
//! `ct-server/src/hash.rs::adjust_hash_for_metadata`.
//!
//! A cofhe handle is `keccak256(ciphertext)` with two trailing bytes overwritten
//! with metadata: the encryption type (and a trivial-encrypt flag) in
//! [`TYPE_BYTE`], and the security zone in [`ZONE_BYTE`]. This is the single
//! definition of that layout on the teecryptor side — the decrypt gate and the
//! e2e test both read it through [`handle_type`] / [`handle_zone`] so they can't
//! drift from each other or silently re-inline the magic numbers.
//!
//! These constants must stay in lockstep with cofhe's `hash.rs`. The tripwire is
//! the e2e test (`tests/e2e_stored_ct.rs`): it reconstructs a handle from a
//! *real* ct-server response using these constants, so any layout change in
//! cofhe makes that reconstruction fail rather than pass silently.

/// Handle byte holding `encryption_type & `[`TYPE_MASK`], with
/// [`TRIVIAL_ENCRYPT_FLAG`] in the top bit for a trivially-encrypted ciphertext.
pub const TYPE_BYTE: usize = 30;

/// Handle byte holding the security zone.
pub const ZONE_BYTE: usize = 31;

/// Mask selecting the encryption type from [`TYPE_BYTE`] (drops the trivial bit).
pub const TYPE_MASK: u8 = 0x7f;

/// Top bit of [`TYPE_BYTE`], set when the ciphertext is trivially encrypted.
pub const TRIVIAL_ENCRYPT_FLAG: u8 = 0x80;

/// The committed encryption type from a 32-byte handle (trivial bit stripped).
pub fn handle_type(handle: &[u8; 32]) -> u8 {
    handle[TYPE_BYTE] & TYPE_MASK
}

/// The committed security zone from a 32-byte handle.
pub fn handle_zone(handle: &[u8; 32]) -> u8 {
    handle[ZONE_BYTE]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_type_and_zone_from_stamped_handle() {
        let mut h = [0u8; 32];
        h[TYPE_BYTE] = 4 | TRIVIAL_ENCRYPT_FLAG; // U32, trivially encrypted
        h[ZONE_BYTE] = 3;
        assert_eq!(handle_type(&h), 4, "trivial flag must be stripped");
        assert_eq!(handle_zone(&h), 3);
    }
}
