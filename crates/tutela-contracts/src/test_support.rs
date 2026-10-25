//! Shared proptest strategies for the unit tests.

use proptest::prelude::*;

use crate::id::Uuid7;

/// Any valid UUIDv7.
pub(crate) fn uuid7_strategy() -> impl Strategy<Value = Uuid7> {
    any::<[u8; 16]>().prop_map(|mut b| {
        b[6] = (b[6] & 0x0f) | 0x70;
        b[8] = (b[8] & 0x3f) | 0x80;
        Uuid7::from_uuid(uuid::Uuid::from_bytes(b)).unwrap()
    })
}
