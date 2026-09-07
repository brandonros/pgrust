//! Bounded, process-owned native WAL bytes for disposable compute.
//! No network publication, record grammar or durable state lives here. A retained
//! byte is readable, NOT remotely durable. The native S3 publisher is
//! responsible for durability confirmation.

use std::collections::BTreeMap;
use std::io;
use pgsync::Mutex;
use types_error::{PgError, PgResult, PANIC};

pgsync::process_global! {
    static STORE: Mutex<Option<RetainedWal>> = Mutex::new(None);
}

pub fn enabled() -> bool {
    guc_tables::backing::pgrust_memory_wal_mb() > 0
}

struct RetainedWal {
    segments: BTreeMap<(u32, u64), Vec<u8>>,
    segment_bytes: usize,
    limit: usize,
    archive_floor: u64,
}

impl RetainedWal {
    fn reap(&mut self, cutoff: u64) -> Option<u64> {
        let floor = self.archive_floor;
        let mut removed = None;
        self.segments.retain(|(_, seg), _| {
            if *seg <= cutoff && *seg < floor {
                removed = Some(removed.map_or(*seg, |old: u64| old.max(*seg)));
                false
            } else { true }
        });
        removed
    }

    fn segment(&mut self, tli: u32, seg: u64) -> io::Result<&mut Vec<u8>> {
        if tli == 0 || seg.checked_add(1).and_then(|end| end.checked_mul(self.segment_bytes as u64)).is_none() {
            return Err(io::Error::other("invalid retained WAL position"));
        }
        if !self.segments.contains_key(&(tli, seg)) {
            if self.segments.len() >= self.limit / self.segment_bytes {
                return Err(io::Error::other("memory WAL capacity exhausted; snapshot renewal or a WAL consumer has fallen behind"));
            }
            self.segments.insert((tli, seg), vec![0; self.segment_bytes]);
        }
        Ok(self.segments.get_mut(&(tli, seg)).unwrap())
    }

    fn write(&mut self, tli: u32, pos: u64, bytes: &[u8]) -> io::Result<()> {
        let size = self.segment_bytes;
        let offset = (pos % size as u64) as usize;
        if bytes.len() > size - offset {
            return Err(io::Error::other("retained WAL write crosses a segment"));
        }
        self.segment(tli, pos / size as u64)?[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn read(&self, tli: u32, mut pos: u64, mut output: &mut [u8]) -> bool {
        while !output.is_empty() {
            let Some(segment) = self.segments.get(&(tli, pos / self.segment_bytes as u64)) else {
                return false;
            };
            let offset = (pos % self.segment_bytes as u64) as usize;
            let count = output.len().min(self.segment_bytes - offset);
            output[..count].copy_from_slice(&segment[offset..offset + count]);
            output = &mut output[count..];
            pos += count as u64;
        }
        true
    }
}

fn failure(error: impl std::fmt::Display) -> Box<PgError> {
    Box::new(PgError::new(PANIC, format!("memory WAL: {error}")))
}

fn report_failure(result: PgResult<()>) -> PgResult<()> {
    match result {
        Ok(()) => Ok(()),
        // Returning a PgError tagged PANIC is insufficient: ordinary callers
        // can treat it as a recoverable ERROR. Invoke the native crash path,
        // after releasing the retained-store mutex, just as disk WAL does.
        Err(error) => elog::ThrowErrorData(*error),
    }
}

/// Install a verified recovery seed before any backend threads start.
pub fn initialize(segments: BTreeMap<(u32, u64), Vec<u8>>, limit: usize, segment_bytes: usize) -> PgResult<()> {
    if segment_bytes == 0 || limit < segment_bytes || segments.is_empty()
        || segments.len() > limit / segment_bytes
        || segments.iter().any(|((tli, seg), b)| *tli == 0 || b.len() != segment_bytes || seg.checked_add(1).and_then(|s| s.checked_mul(segment_bytes as u64)).is_none()) {
        return Err(failure("invalid recovery seed or capacity"));
    }
    let mut guard = pgsync::lock(&STORE);
    if guard.is_some() { return Err(failure("memory WAL already initialized")); }
    let archive_floor = segments.keys().map(|(_, s)| *s).min().unwrap();
    *guard = Some(RetainedWal { segments, segment_bytes, limit, archive_floor });
    Ok(())
}

/// Called only after native checkpoint retention checks, including slots,
/// publication confirmation and unsummarized WAL.
pub fn retire_through(segment: u64) -> Option<u64> {
    pgsync::lock(&STORE).as_mut().and_then(|s| s.reap(segment))
}

/// The publisher advances this only after atomically selecting a recoverable
/// snapshot. Until then it also pins WAL needed by the ongoing export.
pub fn advance_archive_floor(lsn: u64) {
    if let Some(s) = pgsync::lock(&STORE).as_mut() {
        s.archive_floor = s.archive_floor.max(lsn / s.segment_bytes as u64);
    }
}

pub fn initialized() -> bool { pgsync::lock(&STORE).is_some() }

/// Native summarizer discovery uses the same retained segments as WALRead.
pub fn oldest_segment(tli: u32) -> u64 {
    pgsync::lock(&STORE).as_ref().and_then(|s|
        s.segments.range((tli, 0)..=(tli, u64::MAX)).next().map(|((_, seg), _)| *seg)
    ).unwrap_or(0)
}

pub fn contains(tli: u32, seg: u64) -> bool {
    pgsync::lock(&STORE).as_ref().is_some_and(|s| s.segments.contains_key(&(tli, seg)))
}

pub fn missing_bytes() -> PgResult<()> {
    report_failure(Err(failure("required WAL bytes are absent from retained memory")))
}

pub fn read(tli: u32, pos: u64, output: &mut [u8]) -> bool {
    pgsync::lock(&STORE).as_ref().is_some_and(|s| s.read(tli, pos, output))
}

pub fn write(tli: u32, pos: u64, bytes: &[u8]) -> PgResult<()> {
    let result = match pgsync::lock(&STORE).as_mut() {
        Some(store) => store.write(tli, pos, bytes).map_err(failure),
        None => Err(failure("uninitialized store")),
    };
    report_failure(result)
}

pub fn fork(parent: u32, child: u32, end: u64) -> PgResult<()> {
    report_failure(fork_inner(parent, child, end))
}

fn fork_inner(parent: u32, child: u32, end: u64) -> PgResult<()> {
    let mut guard = pgsync::lock(&STORE);
    let store = guard.as_mut().ok_or_else(|| failure("uninitialized store"))?;
    let seg = end / store.segment_bytes as u64;
    let offset = (end % store.segment_bytes as u64) as usize;
    if store.segments.contains_key(&(child, seg)) {
        return Err(failure("child timeline already exists"));
    }
    // Allocate the child first so capacity refusal leaves the parent intact.
    store.segment(child, seg).map_err(failure)?;
    if offset != 0 {
        let prefix = store.segments.get(&(parent, seg)).ok_or_else(|| failure("missing parent prefix"))?[..offset].to_vec();
        store.segments.get_mut(&(child, seg)).unwrap()[..offset].copy_from_slice(&prefix);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_needs_both_native_cutoff_and_selected_archive_floor() {
        let mut s = RetainedWal { segments: BTreeMap::new(), segment_bytes: 16, limit: 64, archive_floor: 2 };
        for n in 1..=4 { s.write(1, n*16, &[n as u8;16]).unwrap(); }
        s.reap(3);
        assert!(!s.segments.contains_key(&(1,1)));
        assert!(s.segments.contains_key(&(1,2)));
        s.archive_floor = 4;
        // Advancing the archive floor alone does not recycle native readers' bytes.
        assert!(s.segments.contains_key(&(1,2)));
        s.reap(2);
        assert!(!s.segments.contains_key(&(1,2)));
        assert!(s.segments.contains_key(&(1,3)));
        s.write(1, 80, &[5;16]).unwrap();
    }

    #[test]
    fn owned_partial_pages_survive_reuse_and_capacity_refusal() {
        let mut s = RetainedWal { segments: BTreeMap::new(), segment_bytes: 16, limit: 32, archive_floor: 1 };
        let mut source = [1; 8];
        s.write(1, 16, &source).unwrap();
        source.fill(9); // insertion ring can now reuse its original storage
        s.write(1, 20, &[2; 4]).unwrap();
        s.write(1, 32, &[3; 16]).unwrap();
        assert!(s.write(1, 48, &[4]).is_err());
        let mut bytes = [0; 24];
        assert!(s.read(1, 24, &mut bytes));
        assert_eq!(&bytes[..8], &[0; 8]);
        assert_eq!(&bytes[8..], &[3; 16]);
        assert!(s.read(1, 16, &mut source));
        assert_eq!(source, [1, 1, 1, 1, 2, 2, 2, 2]);
        assert!(!s.read(2, 16, &mut source));
        assert_eq!(s.segments.len() * s.segment_bytes, s.limit);
    }
}
