//! An LSM key/value store over an object store, with no write-ahead log: a
//! transaction is one immutable object, and their sequence is the log.

/// The on-bucket checksum: CRC-32C with the workspace's init and finalise,
/// one definition for every object kind this crate writes.
pub(crate) fn crc(bytes: &[u8]) -> u32 {
    crc32c::fin_crc32c(crc32c::pg_comp_crc32c(crc32c::CRC32C_INIT, bytes))
}

pub mod bloom;
pub mod index;
pub mod index_key;
pub mod key;
pub mod lease;
pub mod db;
pub mod faults;
pub mod commit;
pub mod run;
pub mod s3;
pub mod store;
