use aien_protocol_types::{Digest32, EventId, SequenceNumber, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub topic: String,
    pub producer: String,
    pub sequence: SequenceNumber,
    pub timestamp: Timestamp,
    pub payload_digest: Digest32,
    pub payload: serde_json::Value,
}
