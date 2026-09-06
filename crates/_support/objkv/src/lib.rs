//! An LSM key/value store over an object store, with no write-ahead log: a
//! transaction is one immutable object, and their sequence is the log.
//!
//! This crate lands in two steps. The object-store client, the run format,
//! the key encodings, the lease and the fault-injection hooks are here; the
//! database engine over them (`db`, `index`) follows in the next change.

pub mod bloom;
pub mod index_key;
pub mod key;
pub mod lease;
pub mod faults;
pub mod commit;
pub mod run;
pub mod s3;
pub mod store;
