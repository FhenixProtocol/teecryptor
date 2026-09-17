// Copied verbatim from FhenixProtocol/cofhe rust-common/src/signing/message_builder.rs
// BORROW-NOT-FORK. Adaptation: build_hash uses Signer::keccak256.

use super::Signer;

/// Trait for types that can be encoded into a signing message (big-endian ints, raw bytes).
pub trait SigningEncode {
    fn encode_to(&self, buffer: &mut Vec<u8>);
}

impl SigningEncode for &[u8] {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(self);
    }
}
impl SigningEncode for Vec<u8> {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(self);
    }
}
impl SigningEncode for &str {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(self.as_bytes());
    }
}
impl SigningEncode for String {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(self.as_bytes());
    }
}
impl SigningEncode for u8 {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.push(*self);
    }
}
impl SigningEncode for u32 {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.to_be_bytes());
    }
}
impl SigningEncode for u64 {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.to_be_bytes());
    }
}
impl SigningEncode for i32 {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.to_be_bytes());
    }
}
impl<const N: usize> SigningEncode for [u8; N] {
    fn encode_to(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(self);
    }
}

/// Builder for abi.encodePacked-style signing messages.
#[derive(Debug, Clone, Default)]
pub struct SigningMessageBuilder {
    buffer: Vec<u8>,
}

impl SigningMessageBuilder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn add<T: SigningEncode>(mut self, value: T) -> Self {
        value.encode_to(&mut self.buffer);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.buffer
    }

    pub fn build_hash(self) -> [u8; 32] {
        Signer::keccak256(&self.buffer)
    }
}
