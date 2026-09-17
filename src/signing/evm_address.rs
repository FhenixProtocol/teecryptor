// Copied verbatim from FhenixProtocol/cofhe rust-common/src/signing/evm_address.rs
// BORROW-NOT-FORK. Adaptation: uses Signer::keccak256.

use super::Signer;

/// EVM address as a 0x-prefixed hex string (e.g., "0x1234...abcd").
pub type EvmAddress = String;

impl From<&Signer> for EvmAddress {
    fn from(signer: &Signer) -> Self {
        let public_key_bytes = signer
            .signing_key()
            .verifying_key()
            .to_encoded_point(false)
            .to_bytes();
        // Skip the 0x04 prefix byte and keccak256 the remaining 64 bytes.
        let key_hash = Signer::keccak256(&public_key_bytes[1..]);
        // Last 20 bytes of the hash.
        format!("0x{}", hex::encode(&key_hash[12..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_address_from_known_key() {
        // Test vector from ethereum/tests keyaddrtest.json
        let pk = hex::decode("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4")
            .unwrap();
        let signer = Signer::from_bytes(&pk).unwrap();
        assert_eq!(
            EvmAddress::from(&signer).to_lowercase(),
            "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"
        );
    }

    #[test]
    fn evm_address_is_42_chars_0x_prefixed() {
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();
        let addr = EvmAddress::from(&signer);
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}
