//! Sorted runs: `run/<id>`, written by compaction, read by ranged GET.
//!
//! Layout — bloom and index are adjacent on purpose, so opening a run costs two
//! ranged GETs (trailer, then bloom+index together) and every subsequent point
//! read costs at most one more:
//!
//! ```text
//! [block 0][block 1]...[bloom][index][trailer]
//! ```
//!
//! A block is ~64KB of sorted entries followed by a CRC32C of them. The index
//! holds each block's first key, so a lookup binary-searches in memory and
//! fetches exactly one block.
//!
//! Every byte a reader trusts is covered by a checksum: the blocks by their
//! own, the bloom and index by `meta_crc`, the trailer fields by
//! `trailer_crc`. A run arrives over the network like a commit object does,
//! and a flipped bit served as a missing row is a wrong answer; verified, it
//! is an error instead.
//!
//! A run also records the collection horizon it was built with: history at
//! or below it was dropped from the run, so a read below it cannot be
//! answered from the run and is refused. Carried here rather than in a
//! marker object of its own so that it cannot fail to land separately from
//! the run whose history it describes.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use crate::bloom::Bloom;
use crate::commit::{get_u32, get_u64, put_u32, put_u64, Op};
use crate::key;

/// Format 3: blocks carry a CRC32C each, the trailer carries its own and the
/// collection horizon. Format 2 runs are refused by name; none were ever
/// written outside tests, so there is nothing to migrate.
pub const MAGIC: u32 = 0x4f4b_5233; // "OKR3"
const MAGIC_V2: u32 = 0x4f4b_5232; // "OKR2"
/// bloom_off u64, bloom_len u32, index_off u64, index_len u32, block_count
/// u32, entry_count u64, horizon u64, meta_crc u32, trailer_crc u32, magic u32.
pub const TRAILER_LEN: u64 = 56;
/// The bytes of the trailer `trailer_crc` covers: everything before it.
const TRAILER_CRC_AT: usize = 48;
/// Every block ends in a CRC32C of the bytes before it.
const BLOCK_CRC_LEN: usize = 4;
pub const TARGET_BLOCK_BYTES: usize = 64 * 1024;
/// Default local block cache. Stands in for the NVMe cache a real deployment
/// would keep; without it every point read is a network round trip and the
/// warm-read threshold is unmeasurable.
pub const DEFAULT_CACHE_BYTES: usize = 64 * 1024 * 1024;

pub fn key_for(id: u64) -> String {
    format!("run/{id:016x}")
}

/// A delta run holds only the commits since the run before it, where a run
/// without the suffix holds everything up to its number.
pub const DELTA_SUFFIX: &str = ".d";

pub fn delta_key_for(id: u64) -> String {
    format!("run/{id:016x}{DELTA_SUFFIX}")
}

pub fn is_delta(key: &str) -> bool {
    key.ends_with(DELTA_SUFFIX)
}

/// A run is live once its seal exists: `sealed/<id>[.d]`, written by the
/// compactor after the run has been read back byte for byte. A run without
/// one is a fold that did not finish -- the PUT failed to be verified, or
/// the process died between the two -- and the next open deletes it. So a
/// torn upload never becomes the run a restart reads.
pub const SEAL_PREFIX: &str = "sealed/";

pub fn seal_key_for(run_key: &str) -> String {
    format!("{SEAL_PREFIX}{}", run_key.strip_prefix("run/").unwrap_or(run_key))
}

/// `sealed/<id>` -> `run/<id>`.
pub fn run_key_of_seal(seal_key: &str) -> Option<String> {
    seal_key.strip_prefix(SEAL_PREFIX).map(|tail| format!("run/{tail}"))
}

fn crc(bytes: &[u8]) -> u32 {
    crc32c::pg_comp_crc32c(0xffff_ffff, bytes) ^ 0xffff_ffff
}

/// Anything a run can be read from: an S3 object, or a byte slice in tests.
pub trait RangeSource {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>>;
    fn size(&self) -> u64;
}

impl RangeSource for &[u8] {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let past = || io::Error::other("range past end of object");
        let s = usize::try_from(offset).map_err(|_| past())?;
        let e = offset.checked_add(len).and_then(|e| usize::try_from(e).ok()).ok_or_else(past)?;
        if e > self.len() {
            return Err(past());
        }
        Ok(self[s..e].to_vec())
    }
    fn size(&self) -> u64 {
        self.len() as u64
    }
}

/// Serialise sorted `(key, op)` pairs into a run object built with the given
/// collection horizon (0 for none; see the module doc).
///
/// Entries must already be sorted by key and deduplicated; compaction owns
/// that, not this function.
pub fn build(entries: &[(Vec<u8>, Op)], horizon: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut index: Vec<(Vec<u8>, u64, u32)> = Vec::new();

    let mut i = 0usize;
    while i < entries.len() {
        let block_off = out.len() as u64;
        let first_key = entries[i].0.clone();
        let start = out.len();
        while i < entries.len() && out.len() - start < TARGET_BLOCK_BYTES {
            let (k, op) = &entries[i];
            put_u32(&mut out, k.len() as u32);
            out.extend_from_slice(k);
            match op {
                Op::Put(v) => {
                    out.push(0);
                    put_u32(&mut out, v.len() as u32);
                    out.extend_from_slice(v);
                }
                Op::Delete => {
                    out.push(1);
                    put_u32(&mut out, 0);
                }
            }
            i += 1;
        }
        let block_crc = crc(&out[start..]);
        put_u32(&mut out, block_crc);
        index.push((first_key, block_off, (out.len() - start) as u32));
    }

    // Bloom over row keys: a seek knows the row, not the version.
    let keys: Vec<&[u8]> = entries
        .iter()
        .map(|(k, _)| key::row_of(k).unwrap_or(k.as_slice()))
        .collect();
    let bloom = Bloom::build(&keys);
    let bloom_off = out.len() as u64;
    out.extend_from_slice(bloom.as_bytes());
    let bloom_len = (out.len() as u64 - bloom_off) as u32;

    let index_off = out.len() as u64;
    for (k, off, len) in &index {
        put_u32(&mut out, k.len() as u32);
        out.extend_from_slice(k);
        put_u64(&mut out, *off);
        put_u32(&mut out, *len);
    }
    let index_len = (out.len() as u64 - index_off) as u32;

    let meta_crc = crc(&out[bloom_off as usize..(index_off + index_len as u64) as usize]);

    let trailer_at = out.len();
    put_u64(&mut out, bloom_off);
    put_u32(&mut out, bloom_len);
    put_u64(&mut out, index_off);
    put_u32(&mut out, index_len);
    put_u32(&mut out, index.len() as u32);
    put_u64(&mut out, entries.len() as u64);
    put_u64(&mut out, horizon);
    put_u32(&mut out, meta_crc);
    debug_assert_eq!(out.len() - trailer_at, TRAILER_CRC_AT);
    let trailer_crc = crc(&out[trailer_at..]);
    put_u32(&mut out, trailer_crc);
    put_u32(&mut out, MAGIC);
    debug_assert_eq!(out.len() - trailer_at, TRAILER_LEN as usize);
    out
}

/// An opened run: bloom and index held locally, blocks fetched on demand.
pub struct Run<S: RangeSource> {
    src: S,
    bloom: Bloom,
    /// (first_key, block_offset, block_len), ascending by first_key.
    index: Vec<(Vec<u8>, u64, u32)>,
    pub entry_count: u64,
    /// History at or below this was dropped when the run was built.
    pub horizon: u64,
    cache: Mutex<BlockCache>,
}

/// FIFO block cache. Not an LRU — the access pattern under test is uniform
/// random, where the two behave the same and FIFO is simpler to reason about.
#[derive(Default)]
struct BlockCache {
    blocks: HashMap<u64, Vec<u8>>,
    order: std::collections::VecDeque<u64>,
    bytes: usize,
    cap: usize,
    pub hits: u64,
    pub misses: u64,
}

impl BlockCache {
    fn get(&mut self, off: u64) -> Option<Vec<u8>> {
        match self.blocks.get(&off) {
            Some(b) => {
                self.hits += 1;
                Some(b.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }
    fn insert(&mut self, off: u64, block: Vec<u8>) {
        if self.cap == 0 || block.len() > self.cap {
            return;
        }
        while self.bytes + block.len() > self.cap {
            let Some(old) = self.order.pop_front() else { break };
            if let Some(b) = self.blocks.remove(&old) {
                self.bytes -= b.len();
            }
        }
        self.bytes += block.len();
        self.order.push_back(off);
        self.blocks.insert(off, block);
    }
}

/// The bloom and index of a run, parsed from wherever its bytes are.
struct Meta {
    bloom: Bloom,
    index: Vec<(Vec<u8>, u64, u32)>,
    entry_count: u64,
    horizon: u64,
}

/// Two ranged reads of `src`: the trailer, then bloom and index in one call.
fn read_meta<S: RangeSource>(src: &S) -> io::Result<Meta> {
    let size = src.size();
    if size < TRAILER_LEN {
        return Err(io::Error::other("object too small to be a run"));
    }
    let t = src.range(size - TRAILER_LEN, TRAILER_LEN)?;
    if t.len() != TRAILER_LEN as usize {
        return Err(io::Error::other("short read of the run trailer"));
    }
    match get_u32(&t, 52) {
        MAGIC => {}
        MAGIC_V2 => {
            return Err(io::Error::other(
                "run is in format 2 (OKR2), which this objkv does not read: it reads format 3 \
                 only, whose blocks and trailer carry checksums. A bucket written by an older \
                 objkv must be migrated, not opened",
            ))
        }
        _ => return Err(io::Error::other("bad run magic")),
    }
    if get_u32(&t, TRAILER_CRC_AT) != crc(&t[..TRAILER_CRC_AT]) {
        return Err(io::Error::other("run trailer checksum mismatch"));
    }
    let bloom_off = get_u64(&t, 0);
    let bloom_len = get_u32(&t, 8) as u64;
    let index_off = get_u64(&t, 12);
    let index_len = get_u32(&t, 20) as u64;
    let block_count = get_u32(&t, 24) as usize;
    let entry_count = get_u64(&t, 28);
    let horizon = get_u64(&t, 36);
    let want_crc = get_u32(&t, 44);
    // The single bloom+index fetch below depends on them being adjacent.
    if bloom_off.checked_add(bloom_len) != Some(index_off)
        || index_off.checked_add(index_len).is_none_or(|end| end > size - TRAILER_LEN)
    {
        return Err(io::Error::other("run metadata is not contiguous"));
    }

    let meta = src.range(bloom_off, bloom_len + index_len)?;
    if meta.len() as u64 != bloom_len + index_len {
        return Err(io::Error::other("short read of the run metadata"));
    }
    if want_crc != crc(&meta) {
        return Err(io::Error::other("run metadata checksum mismatch"));
    }

    let bloom = Bloom::from_bytes(meta[..bloom_len as usize].to_vec());
    let ibytes = &meta[bloom_len as usize..];
    let mut index = Vec::new();
    let mut p = 0usize;
    let short = || io::Error::other("run index is truncated");
    while p < ibytes.len() {
        let klen = crate::commit::get_u32_checked(ibytes, p).ok_or_else(short)? as usize;
        p += 4;
        let key = ibytes.get(p..p.checked_add(klen).ok_or_else(short)?).ok_or_else(short)?.to_vec();
        p += klen;
        let off = ibytes
            .get(p..p + 8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
            .ok_or_else(short)?;
        p += 8;
        let len = crate::commit::get_u32_checked(ibytes, p).ok_or_else(short)?;
        p += 4;
        index.push((key, off, len));
    }
    if index.len() != block_count {
        return Err(io::Error::other("run index does not hold the number of blocks the trailer declares"));
    }
    Ok(Meta { bloom, index, entry_count, horizon })
}

/// A block as fetched, checked against the CRC32C it ends in, and handed on
/// without it. A short ranged GET, a truncated upload or a flipped bit all
/// end here as an error, never as an entry that is not found.
fn verify_block(mut raw: Vec<u8>) -> io::Result<Vec<u8>> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("objkv: {what}"));
    if raw.len() < BLOCK_CRC_LEN {
        return Err(bad("run block shorter than its checksum"));
    }
    let body_len = raw.len() - BLOCK_CRC_LEN;
    let want = get_u32(&raw, body_len);
    if want != crc(&raw[..body_len]) {
        return Err(bad("run block checksum mismatch"));
    }
    raw.truncate(body_len);
    Ok(raw)
}

impl<S: RangeSource> Run<S> {
    /// Two ranged GETs: the trailer, then bloom and index in one call.
    pub fn open(src: S) -> io::Result<Run<S>> {
        let meta = read_meta(&src)?;
        Ok(Run::with_meta(src, meta))
    }

    /// The same run, parsed from a copy of its bytes already in memory --
    /// the compactor has just built it -- so the swap costs no round trip.
    /// Blocks are still read from `src` later.
    pub fn open_from_bytes(src: S, bytes: &[u8]) -> io::Result<Run<S>> {
        if bytes.len() as u64 != src.size() {
            return Err(io::Error::other("run bytes do not match the object size"));
        }
        let meta = read_meta(&bytes)?;
        Ok(Run::with_meta(src, meta))
    }

    fn with_meta(src: S, meta: Meta) -> Run<S> {
        Run {
            src,
            bloom: meta.bloom,
            index: meta.index,
            entry_count: meta.entry_count,
            horizon: meta.horizon,
            cache: Mutex::new(BlockCache { cap: DEFAULT_CACHE_BYTES, ..Default::default() }),
        }
    }

    /// Where the run is read from: the object it lives in.
    pub fn source(&self) -> &S {
        &self.src
    }

    /// The sequence number of the version live at `snapshot`.
    pub fn seq_at(&self, row_key: &[u8], snapshot: u64) -> io::Result<Option<u64>> {
        Ok(self.locate_at(row_key, snapshot)?.and_then(|(k, _)| key::seq_of(&k)))
    }

    /// The version of `row_key` live at `snapshot`. At most one ranged GET.
    pub fn get_at(&self, row_key: &[u8], snapshot: u64) -> io::Result<Option<Op>> {
        Ok(self.locate_at(row_key, snapshot)?.map(|(_, op)| op))
    }

    /// One block, from the cache or one ranged GET. Verified on the way in,
    /// so the cache holds only blocks that checked out.
    fn block_at(&self, off: u64, len: u32) -> io::Result<Vec<u8>> {
        // Scoped: inlining this into a match holds the guard across the miss
        // arm and self-deadlocks.
        let cached = self.cache.lock().unwrap().get(off);
        match cached {
            Some(b) => Ok(b),
            None => {
                let b = verify_block(self.src.range(off, len as u64)?)?;
                self.cache.lock().unwrap().insert(off, b.clone());
                Ok(b)
            }
        }
    }

    /// Every stored key in `[lo, hi)`, in order, stopping once `limit`
    /// distinct rows have been seen.
    ///
    /// Bounds are plain byte strings and the range is half-open, so "greater
    /// than this value" and "up to and including it" are both expressed by
    /// where the caller puts the bound rather than by a flag here.
    ///
    /// Stored keys carry a version suffix, so one row can appear several
    /// times; the limit counts rows. Taking the first `limit` from each layer
    /// and merging afterwards is safe: a key among the first `limit` of the
    /// union is among the first `limit` of whichever layer holds it.
    ///
    /// Versions above `snapshot` are left out here rather than by the caller.
    /// Counted, they would fill the page with rows the snapshot cannot see,
    /// and a page that came back short would be mistaken for the end of the
    /// range.
    pub fn scan_range_limited(
        &self,
        lo: &[u8],
        hi: &[u8],
        snapshot: u64,
        limit: usize,
    ) -> io::Result<Vec<(Vec<u8>, Op)>> {
        if self.index.is_empty() || lo >= hi || limit == 0 {
            return Ok(Vec::new());
        }
        let mut rows = 0usize;
        let mut last: Option<Vec<u8>> = None;
        let start = match self.index.binary_search_by(|(k, _, _)| k.as_slice().cmp(lo)) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let mut out = Vec::new();
        for pos in start..self.index.len() {
            let (first, off, len) = &self.index[pos];
            // Blocks are ordered: once one starts at or past the upper bound,
            // so does every block after it.
            if first.as_slice() >= hi {
                break;
            }
            let block = self.block_at(*off, *len)?;
            let mut past = false;
            for (k, op) in decode_block(&block)? {
                // The bounds name rows, and a caller resuming a page passes
                // the last row it saw plus a zero byte. That sits below the
                // row's own versions, which carry `/`, so the whole key would
                // compare above it and the row would come back twice.
                if crate::key::row_of(&k).unwrap_or(&k) < lo {
                    continue;
                }
                if k.as_slice() >= hi {
                    past = true;
                    break;
                }
                if crate::key::seq_of(&k).is_some_and(|seq| seq > snapshot) {
                    continue;
                }
                let row = crate::key::row_of(&k).map(|r| r.to_vec());
                if row.is_some() && row != last {
                    if rows == limit {
                        past = true;
                        break;
                    }
                    rows += 1;
                    last = row;
                }
                out.push((k, op));
            }
            if past {
                break;
            }
        }
        Ok(out)
    }

    /// The last `limit` rows of `[lo, hi)`, still in ascending order.
    ///
    /// Blocks are walked from the top down so a scan reading backwards stops
    /// as early as a forward one does; ORDER BY ... DESC LIMIT 10 is the whole
    /// reason it exists.
    pub fn scan_range_back(
        &self,
        lo: &[u8],
        hi: &[u8],
        snapshot: u64,
        limit: usize,
    ) -> io::Result<Vec<(Vec<u8>, Op)>> {
        if self.index.is_empty() || lo >= hi || limit == 0 {
            return Ok(Vec::new());
        }
        let mut rows = 0usize;
        let mut last: Option<Vec<u8>> = None;
        let mut out: Vec<(Vec<u8>, Op)> = Vec::new();
        for pos in (0..self.index.len()).rev() {
            let (first, off, len) = &self.index[pos];
            // Once a block starts at or past the top of the range, nothing in
            // it is wanted; once one starts below the bottom, this is the last.
            if first.as_slice() >= hi {
                continue;
            }
            let block = self.block_at(*off, *len)?;
            let mut done = false;
            let entries = decode_block(&block)?;
            for (k, op) in entries.into_iter().rev() {
                if k.as_slice() >= hi {
                    continue;
                }
                if crate::key::row_of(&k).unwrap_or(&k) < lo {
                    done = true;
                    break;
                }
                if crate::key::seq_of(&k).is_some_and(|seq| seq > snapshot) {
                    continue;
                }
                let row = crate::key::row_of(&k).map(|r| r.to_vec());
                if row.is_some() && row != last {
                    if rows == limit {
                        done = true;
                        break;
                    }
                    rows += 1;
                    last = row;
                }
                out.push((k, op));
            }
            if done || first.as_slice() <= lo {
                break;
            }
        }
        out.reverse();
        Ok(out)
    }

    /// Every entry whose key starts with `prefix`, in key order.
    ///
    /// Seeks rather than scans: the sparse index picks the first block that
    /// can hold the prefix, and the walk stops at the first key past it. This
    /// is what makes an index lookup cost a couple of ranged GETs instead of a
    /// read of the whole run -- the difference between an index being worth
    /// having and not.
    pub fn scan_prefix(&self, prefix: &[u8]) -> io::Result<Vec<(Vec<u8>, Op)>> {
        if self.index.is_empty() {
            return Ok(Vec::new());
        }
        let start = match self.index.binary_search_by(|(k, _, _)| k.as_slice().cmp(prefix)) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let mut out = Vec::new();
        for pos in start..self.index.len() {
            let (first, off, len) = &self.index[pos];
            // Blocks are ordered, so once one starts past the prefix, every
            // block after it does too.
            if first.as_slice() > prefix && !first.starts_with(prefix) {
                break;
            }
            let block = self.block_at(*off, *len)?;
            let mut past = false;
            for (k, op) in decode_block(&block)? {
                if k.as_slice() < prefix {
                    continue;
                }
                if !k.starts_with(prefix) {
                    past = true;
                    break;
                }
                out.push((k, op));
            }
            if past {
                break;
            }
        }
        Ok(out)
    }

    /// The version of `row_key` live at `snapshot`, with its versioned key,
    /// so the caller can read the sequence number off it.
    pub fn locate_at(&self, row_key: &[u8], snapshot: u64) -> io::Result<Option<(Vec<u8>, Op)>> {
        if !self.bloom.may_contain(row_key) || self.index.is_empty() {
            return Ok(None);
        }
        let probe = key::seek_at(row_key, snapshot);
        let start = match self.index.binary_search_by(|(k, _, _)| k.as_slice().cmp(&probe)) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        // The wanted entry may be the first entry of the next block.
        for pos in start..self.index.len().min(start + 2) {
            let (_, off, len) = &self.index[pos];
            let block = self.block_at(*off, *len)?;
            if let Some((found, op)) = seek_block(&block, &probe)? {
                return Ok(key::belongs_to(&found, row_key).then_some((found, op)));
            }
        }
        Ok(None)
    }

    pub fn block_count(&self) -> usize {
        self.index.len()
    }

    /// (hits, misses) against the local block cache.
    pub fn cache_stats(&self) -> (u64, u64) {
        let c = self.cache.lock().unwrap();
        (c.hits, c.misses)
    }

    pub fn set_cache_bytes(&self, cap: usize) {
        self.cache.lock().unwrap().cap = cap;
    }

    /// Every entry in key order, tombstones included. Used by compaction: one
    /// ranged GET per block, straight from the source and past the cache,
    /// since nothing it reads will be read again -- the one read path that is
    /// allowed to be expensive.
    pub fn scan(&self) -> io::Result<Vec<(Vec<u8>, Op)>> {
        // No with_capacity on entry_count: it comes off the trailer, which no
        // checksum covers, and a wrong value here asks the allocator for it.
        let mut out = Vec::new();
        for (_, off, len) in &self.index {
            out.extend(decode_block(&verify_block(self.src.range(*off, *len as u64)?)?)?);
        }
        Ok(out)
    }
}

/// Every entry in one verified block, in key order.
///
/// Still bounds-checked at every step, checksum or no checksum. A run object
/// arrives over the network like a commit object does, and `commit::decode`
/// already states the rule: length fields may disagree with the buffer they
/// came in, and unchecked slicing would take the backend down rather than
/// report a bad object.
fn decode_block(block: &[u8]) -> io::Result<Vec<(Vec<u8>, Op)>> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 4 <= block.len() {
        let (k, tag, value, next) = entry_at(block, p)?;
        out.push((k.to_vec(), if tag == 0 { Op::Put(value.to_vec()) } else { Op::Delete }));
        p = next;
    }
    Ok(out)
}

/// First entry at or after `probe` within one block, if any.
fn seek_block(block: &[u8], probe: &[u8]) -> io::Result<Option<(Vec<u8>, Op)>> {
    let mut p = 0usize;
    while p + 4 <= block.len() {
        let (k, tag, value, next) = entry_at(block, p)?;
        if k >= probe {
            return Ok(Some((
                k.to_vec(),
                if tag == 0 { Op::Put(value.to_vec()) } else { Op::Delete },
            )));
        }
        p = next;
    }
    Ok(None)
}

/// One encoded entry at `p`: key, tag, value, and where the next one starts.
fn entry_at(block: &[u8], p: usize) -> io::Result<(&[u8], u8, &[u8], usize)> {
    fn short<T>() -> io::Result<T> {
        Err(io::Error::new(io::ErrorKind::InvalidData, "objkv: truncated run block"))
    }
    let take = |at: usize, n: usize| -> io::Result<(&[u8], usize)> {
        match block.get(at..at + n) {
            Some(s) => Ok((s, at + n)),
            None => short(),
        }
    };
    let (klen_bytes, p) = take(p, 4)?;
    let klen = u32::from_le_bytes(klen_bytes.try_into().expect("4 bytes")) as usize;
    let (k, p) = take(p, klen)?;
    let (tag_byte, p) = take(p, 1)?;
    let (vlen_bytes, p) = take(p, 4)?;
    let vlen = u32::from_le_bytes(vlen_bytes.try_into().expect("4 bytes")) as usize;
    let (value, p) = take(p, vlen)?;
    Ok((k, tag_byte[0], value, p))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LATEST;

    /// Counts ranged reads so tests can assert the round-trip budget, which is
    /// the whole point of the layout.
    struct Counting<'a> {
        bytes: &'a [u8],
        reads: std::cell::Cell<usize>,
    }
    impl RangeSource for Counting<'_> {
        fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
            self.reads.set(self.reads.get() + 1);
            self.bytes.range(offset, len)
        }
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }
    }

    fn row(i: usize) -> Vec<u8> {
        format!("key{i:08}").into_bytes()
    }

    /// One version of each row, all stamped at seq 1.
    fn entries(n: usize) -> Vec<(Vec<u8>, Op)> {
        let mut e: Vec<(Vec<u8>, Op)> = (0..n)
            .map(|i| (key::versioned(&row(i), 1), Op::Put(vec![b'v'; 100])))
            .collect();
        e.sort_by(|a, b| a.0.cmp(&b.0));
        e
    }

    #[test]
    fn finds_every_key_it_stored() {
        let e = entries(5000);
        let bytes = build(&e, 0);
        let run = Run::open(bytes.as_slice()).unwrap();
        assert_eq!(run.entry_count, 5000);
        assert!(run.block_count() > 1, "should span several blocks");
        for (k, v) in &e {
            let r = key::row_of(k).unwrap();
            assert_eq!(run.get_at(r, LATEST).unwrap().as_ref(), Some(v));
        }
    }

    #[test]
    fn point_read_costs_one_ranged_get_after_open() {
        let bytes = build(&entries(5000), 0);
        let src = Counting { bytes: bytes.as_slice(), reads: std::cell::Cell::new(0) };
        let run = Run::open(src).unwrap();
        run.set_cache_bytes(0); // measure raw GETs, not cache behaviour
        // open() = trailer + (bloom+index) = 2.
        assert_eq!(run.src.reads.get(), 2);
        run.get_at(b"key00002500", LATEST).unwrap();
        assert_eq!(run.src.reads.get(), 3, "a hit must cost exactly one more GET");
    }

    #[test]
    fn absent_keys_usually_cost_nothing() {
        let bytes = build(&entries(2000), 0);
        let src = Counting { bytes: bytes.as_slice(), reads: std::cell::Cell::new(0) };
        let run = Run::open(src).unwrap();
        let before = run.src.reads.get();
        for i in 0..500 {
            let k = format!("absent{i:08}");
            assert!(run.get_at(k.as_bytes(), LATEST).unwrap().is_none());
        }
        let fetched = run.src.reads.get() - before;
        // Bloom should reject nearly all of them without touching a block.
        assert!(fetched < 50, "bloom let {fetched}/500 misses through to a GET");
    }

    #[test]
    fn cache_turns_a_repeat_read_into_zero_gets() {
        let bytes = build(&entries(5000), 0);
        let src = Counting { bytes: bytes.as_slice(), reads: std::cell::Cell::new(0) };
        let run = Run::open(src).unwrap();
        let k = b"key00002500";
        run.get_at(k, LATEST).unwrap();
        let after_first = run.src.reads.get();
        for _ in 0..100 {
            run.get_at(k, LATEST).unwrap();
        }
        assert_eq!(run.src.reads.get(), after_first, "repeat reads must be free");
        let (hits, misses) = run.cache_stats();
        assert_eq!((hits, misses), (100, 1));
    }

    #[test]
    fn a_prefix_scan_seeks_instead_of_reading_the_run() {
        // The property an index lookup lives or dies on. A run holding many
        // rows must answer "everything under this prefix" with a couple of
        // ranged GETs, not one per block.
        let mut e: Vec<(Vec<u8>, Op)> = Vec::new();
        for i in 0..20_000usize {
            // Two prefixes, interleaved so neither is contiguous by accident.
            let p = if i % 2 == 0 { "aaa" } else { "bbb" };
            e.push((
                key::versioned(format!("{p}/{i:08}").as_bytes(), 1),
                Op::Put(vec![b'v'; 60]),
            ));
        }
        e.sort_by(|a, b| a.0.cmp(&b.0));
        let bytes = build(&e, 0);
        let src = Counting { bytes: &bytes, reads: Default::default() };
        let run = Run::open(src).unwrap();
        assert!(run.block_count() > 10, "needs enough blocks for the test to mean anything");

        let before = run.src.reads.get();
        let hits = run.scan_prefix(b"aaa/00000042").unwrap();
        let reads = run.src.reads.get() - before;
        assert_eq!(hits.len(), 1);
        assert!(reads <= 2, "a point prefix cost {reads} ranged GETs, not a seek");

        // A wide prefix reads only its own share of the run.
        let before = run.src.reads.get();
        let all_a = run.scan_prefix(b"aaa/").unwrap();
        let reads = run.src.reads.get() - before;
        assert_eq!(all_a.len(), 10_000);
        assert!(
            reads < run.block_count(),
            "reading half the keys touched {reads} of {} blocks",
            run.block_count()
        );

        assert!(run.scan_prefix(b"zzz/").unwrap().is_empty());
        assert_eq!(run.scan_prefix(b"").unwrap().len(), 20_000);
    }

    #[test]
    fn scan_returns_everything_in_key_order() {
        let e = entries(3000);
        let bytes = build(&e, 0);
        let run = Run::open(bytes.as_slice()).unwrap();
        let got = run.scan().unwrap();
        assert_eq!(got.len(), e.len());
        assert!(got.windows(2).all(|w| w[0].0 < w[1].0), "scan must be sorted");
        assert_eq!(got[0].0, e[0].0);
    }

    #[test]
    fn preserves_tombstones() {
        let mut e = vec![
            (key::versioned(b"a", 1), Op::Put(b"1".to_vec())),
            (key::versioned(b"b", 1), Op::Delete),
        ];
        e.sort_by(|x, y| x.0.cmp(&y.0));
        let bytes = build(&e, 0);
        let run = Run::open(bytes.as_slice()).unwrap();
        assert_eq!(run.get_at(b"b", LATEST).unwrap(), Some(Op::Delete));
        assert_eq!(run.get_at(b"c", LATEST).unwrap(), None);
    }

    #[test]
    fn a_run_opened_from_its_bytes_reads_no_metadata_over_the_wire() {
        let bytes = build(&entries(3000), 0);
        let src = Counting { bytes: bytes.as_slice(), reads: std::cell::Cell::new(0) };
        let run = Run::open_from_bytes(src, &bytes).unwrap();
        assert_eq!(run.src.reads.get(), 0, "trailer and index came from memory");
        assert_eq!(run.entry_count, 3000);
        assert_eq!(run.get_at(b"key00000042", LATEST).unwrap(), Some(Op::Put(vec![b'v'; 100])));
        assert_eq!(run.src.reads.get(), 1, "the block itself still comes from the source");

        let short = &bytes[..bytes.len() - 1];
        assert!(Run::open_from_bytes(short, &bytes).is_err(), "size mismatch is refused");
    }

    #[test]
    fn detects_metadata_corruption() {
        let mut bytes = build(&entries(100), 0);
        let n = bytes.len();
        bytes[n - (TRAILER_LEN as usize) - 5] ^= 0xff;
        assert!(Run::open(bytes.as_slice()).is_err());
    }

    #[test]
    fn a_flipped_bit_in_a_block_is_an_error_not_a_missing_row() {
        // The finding this guards: without a block checksum a flipped key
        // byte makes the seek skip the entry and the row reads as absent, and
        // a flipped value byte is served as the value. Every bit of every
        // block, flipped one at a time, must come back as an error from the
        // point read that lands on it and from a full scan.
        let e = entries(40);
        let good = build(&e, 0);
        let run = Run::open(good.as_slice()).unwrap();
        let (_, first_off, first_len) = run.index[0].clone();
        assert_eq!(first_off, 0);
        let mut checked = 0;
        for byte in (0..first_len as usize).step_by(13) {
            for bit in 0..8 {
                let mut torn = good.clone();
                torn[byte] ^= 1 << bit;
                let run = Run::open(torn.as_slice()).unwrap();
                run.set_cache_bytes(0);
                let scan = run.scan();
                assert!(scan.is_err(), "byte {byte} bit {bit}: scan served a torn block");
                for (k, _) in &e {
                    let r = key::row_of(k).unwrap();
                    let got = run.get_at(r, LATEST);
                    if !matches!(got, Ok(Some(_)) | Err(_)) {
                        panic!("byte {byte} bit {bit}: row {:?} read as missing", String::from_utf8_lossy(r));
                    }
                    if let Ok(Some(v)) = &got {
                        assert_eq!(v, &e.iter().find(|(kk, _)| kk == k).unwrap().1, "a wrong value came back");
                    }
                }
                checked += 1;
            }
        }
        assert!(checked > 100);
        let err = {
            let mut torn = good.clone();
            torn[3] ^= 0x01;
            Run::open(torn.as_slice()).unwrap().scan().unwrap_err()
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    #[test]
    fn a_short_block_read_is_an_error_not_a_missing_row() {
        struct Short<'a>(&'a [u8]);
        impl RangeSource for Short<'_> {
            fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
                let full = self.0.range(offset, len)?;
                // The trailer and metadata come back whole; a block comes back
                // short, as a ranged GET that was cut off does.
                if offset + len < self.0.len() as u64 - TRAILER_LEN {
                    Ok(full[..full.len() / 2].to_vec())
                } else {
                    Ok(full)
                }
            }
            fn size(&self) -> u64 {
                self.0.len() as u64
            }
        }
        let bytes = build(&entries(50), 0);
        let run = Run::open(Short(&bytes)).unwrap();
        assert!(run.get_at(b"key00000010", LATEST).is_err());
        assert!(run.scan().is_err());
    }

    #[test]
    fn a_flipped_bit_in_the_trailer_is_detected() {
        let good = build(&entries(100), 0);
        let n = good.len();
        // Every field but the magic (which has its own check) is covered.
        for byte in n - TRAILER_LEN as usize..n - 4 {
            let mut torn = good.clone();
            torn[byte] ^= 0x10;
            let err = Run::open(torn.as_slice()).map(|_| ()).unwrap_err().to_string();
            assert!(
                err.contains("checksum") || err.contains("magic"),
                "trailer byte {} flipped: {err}",
                byte - (n - TRAILER_LEN as usize)
            );
        }
    }

    #[test]
    fn an_older_run_format_is_refused_by_name() {
        let mut bytes = build(&entries(10), 0);
        let n = bytes.len();
        bytes[n - 4..].copy_from_slice(&MAGIC_V2.to_le_bytes());
        let err = Run::open(bytes.as_slice()).map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("format 2"), "{err}");
        assert!(err.contains("format 3"), "{err}");
        bytes[n - 4..].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert!(Run::open(bytes.as_slice()).map(|_| ()).unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn the_horizon_rides_in_the_trailer() {
        let e = entries(10);
        let plain = build(&e, 0);
        assert_eq!(Run::open(plain.as_slice()).unwrap().horizon, 0);
        let bytes = build(&e, 42);
        let run = Run::open(bytes.as_slice()).unwrap();
        assert_eq!(run.horizon, 42);
        assert_eq!(run.entry_count, 10, "and the count still reads");
        let run = Run::open_from_bytes(bytes.as_slice(), &bytes).unwrap();
        assert_eq!(run.horizon, 42);
    }

    #[test]
    fn seal_keys_mirror_run_keys() {
        assert_eq!(seal_key_for(&key_for(5)), "sealed/0000000000000005");
        assert_eq!(seal_key_for(&delta_key_for(5)), "sealed/0000000000000005.d");
        assert_eq!(run_key_of_seal("sealed/0000000000000005.d").as_deref(), Some("run/0000000000000005.d"));
        assert_eq!(run_key_of_seal(&key_for(5)), None);
    }

    #[test]
    fn a_run_answers_at_any_snapshot_it_holds() {
        // Three versions of one row, plus enough neighbours to span blocks, so
        // the seek has to do real work rather than land on entry zero.
        let mut e: Vec<(Vec<u8>, Op)> = Vec::new();
        for i in 0..2000 {
            e.push((key::versioned(&row(i), 1), Op::Put(vec![b'p'; 60])));
        }
        e.push((key::versioned(&row(900), 4), Op::Put(b"at-four".to_vec())));
        e.push((key::versioned(&row(900), 9), Op::Put(b"at-nine".to_vec())));
        e.push((key::versioned(&row(901), 7), Op::Delete));
        e.sort_by(|a, b| a.0.cmp(&b.0));

        let bytes = build(&e, 0);
        let run = Run::open(bytes.as_slice()).unwrap();
        let val = |snap| match run.get_at(&row(900), snap).unwrap() {
            Some(Op::Put(v)) => String::from_utf8(v).unwrap(),
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(val(LATEST), "at-nine");
        assert_eq!(val(9), "at-nine");
        assert_eq!(val(8), "at-four", "snapshot 8 predates version 9");
        assert_eq!(val(4), "at-four");
        assert_eq!(val(3).len(), 60, "before either update, the original");
        assert_eq!(run.get_at(&row(900), 0).unwrap(), None, "before it existed");

        // A tombstone is a version like any other: visible as deleted after it,
        // and invisible before it.
        assert_eq!(run.get_at(&row(901), LATEST).unwrap(), Some(Op::Delete));
        assert!(matches!(run.get_at(&row(901), 6).unwrap(), Some(Op::Put(_))));
    }

}
