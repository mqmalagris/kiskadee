//! Canonical byte encoding of a Ledger row, version 1.
//!
//! **Frozen.** Changing anything here breaks verification of every Ledger
//! already written; a new encoding needs a new domain string and a migration
//! path. The pinned test vector below exists to catch accidental changes.
//!
//! ```text
//! canonical(row) = "kiskadee/ledger/v1"
//!                  || field(seq) || field(ts_ms) || field(kind)
//!                  || field(actor) || field(account) || field(verb)
//!                  || field(target) || field(args_digest)
//!                  || field(begin_seq) || field(status) || field(detail)
//!
//! field(NULL)    = 0x00
//! field(integer) = 0x01 || i64 big-endian (8 bytes)
//! field(text)    = 0x02 || u32 big-endian byte length || UTF-8 bytes
//! field(blob)    = 0x03 || u32 big-endian byte length || bytes
//!
//! hash(row)      = SHA-256(prev_hash || canonical(row))
//! prev_hash      = hash of the row before it; 32 zero bytes for seq 1
//! ```
//!
//! Fields map one-to-one, in this order, to the columns of the `entries`
//! table, so `ledger verify` can recompute a hash from the stored column
//! values without trusting any parsing of them.

use sha2::{Digest, Sha256};

pub(crate) const DOMAIN: &[u8] = b"kiskadee/ledger/v1";

/// `prev_hash` of the first row.
pub const GENESIS: [u8; 32] = [0; 32];

/// The column values of one row, in canonical order.
pub(crate) const COLUMNS: &str =
    "seq, ts_ms, kind, actor, account, verb, target, args_digest, begin_seq, status, detail";

/// Number of fields in [`COLUMNS`].
pub(crate) const FIELD_COUNT: usize = 11;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Field<'a> {
    Null,
    Int(i64),
    Text(&'a str),
    Blob(&'a [u8]),
}

impl<'a> Field<'a> {
    pub(crate) fn text(value: Option<&'a str>) -> Self {
        value.map_or(Field::Null, Field::Text)
    }
}

pub(crate) fn canonical(fields: &[Field<'_>]) -> Vec<u8> {
    encode(DOMAIN, fields)
}

/// The field encoding above under another domain string, for other
/// records that need an unambiguous byte form (`tokens.db` rows).
pub(crate) fn encode(domain: &[u8], fields: &[Field<'_>]) -> Vec<u8> {
    let mut out = domain.to_vec();
    for field in fields {
        match field {
            Field::Null => out.push(0x00),
            Field::Int(value) => {
                out.push(0x01);
                out.extend_from_slice(&value.to_be_bytes());
            }
            Field::Text(value) => length_prefixed(&mut out, 0x02, value.as_bytes()),
            Field::Blob(value) => length_prefixed(&mut out, 0x03, value),
        }
    }
    out
}

fn length_prefixed(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    // Ledger fields are small (ids, verbs, digests); a field over 4 GiB is a bug.
    let length = u32::try_from(bytes.len()).expect("ledger field longer than u32::MAX");
    out.push(tag);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn chain(prev_hash: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(canonical);
    hasher.finalize().into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned v1 test vector. If this fails, the encoding changed and every
    /// existing Ledger would stop verifying: revert, don't update the vector.
    #[test]
    fn v1_test_vector_is_stable() {
        let digest = [0xab; 32];
        let fields = [
            Field::Int(1),
            Field::Int(1_793_000_000_000),
            Field::Text("begin"),
            Field::Text("token:t1"),
            Field::Text("work"),
            Field::Text("mail.list"),
            Field::Null,
            Field::Blob(&digest),
            Field::Null,
            Field::Null,
            Field::Null,
        ];
        let bytes = canonical(&fields);
        assert_eq!(
            hex(&bytes),
            concat!(
                "6b69736b616465652f6c65646765722f7631",
                "010000000000000001",
                "01000001a17720ca00",
                "0200000005626567696e",
                "0200000008746f6b656e3a7431",
                "0200000004776f726b",
                "02000000096d61696c2e6c697374",
                "00",
                "0300000020abababababababababababababababababababababababababababababababab",
                "00",
                "00",
                "00",
            )
        );
        // Computed independently (Python hashlib) from the bytes above.
        assert_eq!(
            hex(&chain(&GENESIS, &bytes)),
            "026d7f9c00c412b8ce5510066b7661b68cd82d9b5a25e055df60d3362ab272ff"
        );
    }

    #[test]
    fn field_count_matches_the_column_list() {
        assert_eq!(COLUMNS.split(", ").count(), FIELD_COUNT);
    }

    #[test]
    fn text_and_blob_with_same_bytes_encode_differently() {
        assert_ne!(
            canonical(&[Field::Text("ab")]),
            canonical(&[Field::Blob(b"ab")])
        );
    }

    #[test]
    fn null_and_empty_text_encode_differently() {
        assert_ne!(canonical(&[Field::Null]), canonical(&[Field::Text("")]));
    }
}
