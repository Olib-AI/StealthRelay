//! Serde helpers for byte arrays larger than 32 elements.
//!
//! The `serde` crate only implements `Serialize`/`Deserialize` for arrays up to
//! `[T; 32]`. This module provides custom serialize/deserialize functions for
//! `[u8; 64]` using base64 encoding.

/// Serde helper for `[u8; 64]` — serializes as a base64 string.
pub mod bytes64 {
    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Base64::encode_string(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded = Base64::decode_vec(&s).map_err(serde::de::Error::custom)?;
        if decoded.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                decoded.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}
