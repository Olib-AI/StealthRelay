use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Mirror of the iOS `PoolMessageType` enum.
///
/// The server understands these variants for routing decisions but never
/// inspects the encrypted payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MessageType {
    Chat,
    GameState,
    GameAction,
    GameControl,
    System,
    Ping,
    Pong,
    PeerInfo,
    ProfileUpdate,
    KeyExchange,
    Relay,
    Custom,
}

/// Server's routing view of a `PoolMessage`.
///
/// The `payload` field is opaque -- the server never decrypts it.
/// It is serialized on the wire as base64 to match the iOS JSON format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMessage {
    pub id: Uuid,

    #[serde(rename = "type")]
    pub msg_type: MessageType,

    #[serde(rename = "senderID")]
    pub sender_id: String,

    #[serde(rename = "senderName")]
    pub sender_name: String,

    pub timestamp: f64,

    /// Opaque payload -- E2E encrypted, server never reads this.
    #[serde(with = "base64_serde")]
    pub payload: Vec<u8>,

    #[serde(rename = "isReliable")]
    pub is_reliable: bool,
}

/// Serde helper that encodes `Vec<u8>` as standard base64 in JSON.
mod base64_serde {
    use base64ct::{Base64, Encoding};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Base64::encode_string(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Base64::decode_vec(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_pool_message() {
        let msg = PoolMessage {
            id: Uuid::nil(),
            msg_type: MessageType::Chat,
            sender_id: "peer-1".into(),
            sender_name: "Alice".into(),
            timestamp: 1_700_000_000.0,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            is_reliable: true,
        };

        let json = serde_json::to_string(&msg).expect("serialize");
        let deserialized: PoolMessage = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(deserialized.msg_type, MessageType::Chat);
        assert_eq!(deserialized.sender_id, "peer-1");
    }

    #[test]
    fn payload_is_base64_in_json() {
        let msg = PoolMessage {
            id: Uuid::nil(),
            msg_type: MessageType::Ping,
            sender_id: String::new(),
            sender_name: String::new(),
            timestamp: 0.0,
            payload: vec![1, 2, 3],
            is_reliable: false,
        };

        let json = serde_json::to_string(&msg).expect("serialize");
        // base64 of [1,2,3] is "AQID"
        assert!(
            json.contains("AQID"),
            "payload should be base64-encoded: {json}"
        );
    }
}
