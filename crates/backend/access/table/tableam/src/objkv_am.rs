//! The objkv table access method: rows are key/value entries whose durable
//! form is immutable objects in an object store.
//!
//! Unlike heap: no pages, so no buffer or storage manager; no xmin/xmax, since
//! visibility follows the commit sequence number that wrote the row; no WAL,
//! because the numbered commit objects are both log and data. Writes buffer
//! per backend and are numbered and validated at pre-commit; one writer
//! thread then lands everything queued in one PUT, so a 1000-row INSERT
//! costs one PUT and so do eight transactions committing at once. Two
//! transactions writing one row do not block: the first wins, the second
//! gets 40001. The full contract, including every deliberate divergence from
//! PostgreSQL, is in `docs/objkv.md`.
//!
//! Missing on purpose, and errors rather than pretending: TABLESAMPLE,
//! parallel scan. ANALYZE works: `analyze` samples through the ordinary
//! scan path (`getnextslot`), not through the heap's per-block sampler.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use ::datum::Datum;
use ::objkv::commit::Op;
use ::objkv::db::{Db, Outcome};
use ::objkv::store::{MemStore, Store};
use ::types_core::xact::{CommandId, InvalidCommandId, SubTransactionId};
use ::types_error::{PgError, PgResult};
use ::types_tuple::TupleDescData;

use ::mcx::Mcx;
use ::types_rel::Relation;
use ::types_slot::SlotData;
use ::types_snapshot::SnapshotData;

use ::types_tuple::{
    HeapTupleData, ItemPointerData, ItemPointerGetBlockNumber, ItemPointerGetOffsetNumber,
    ItemPointerSet,
};

use crate::{TableScanDesc, TableScanDescData};

/// Process-global: a thread per backend, so thread_local would give every
/// connection its own copy of the database.
static STORE: OnceLock<Arc<dyn Store>> = OnceLock::new();
static DB: Mutex<Option<Db>> = Mutex::new(None);
static NEXT_ROW: Mutex<Option<HashMap<(u32, u32), u64>>> = Mutex::new(None);
/// Live (bytes, rows) per relation: the local file is 0 bytes, so without this
/// the planner sizes every objkv table as empty. ANALYZE refreshes
/// pg_class.reltuples from a sample; this is what `relation_estimate_size`
/// reads in between, tracked at stage time and never corrected by an abort.
static REL_STATS: Mutex<Option<HashMap<(u32, u32), (u64, u64)>>> = Mutex::new(None);

/// One subtransaction's writes, keyed by id: a savepoint opened before our
/// first write delivers no START_SUB.
struct Frame {
    subid: SubTransactionId,
    /// Keyed by object key.
    writes: BTreeMap<Vec<u8>, Staged>,
}

/// The stamp of a write every command sees, its own included: the in-place
/// catalog update, which heap makes visible at once by rewriting the tuple
/// where it stands. No command ever has this id.
const SEEN_BY_ALL: CommandId = InvalidCommandId;

/// Whether a command reading at `curcid` sees a write stamped `cid`: heap's
/// `cmin < curcid`. A statement does not see its own writes -- or `UPDATE t
/// SET k = k + 1 WHERE k > 5` would find the rows it moved in a later scan
/// window and move them again -- and sees them from the next
/// CommandCounterIncrement on.
fn seen_by(cid: CommandId, curcid: CommandId) -> bool {
    cid == SEEN_BY_ALL || cid < curcid
}

/// One of this transaction's uncommitted writes, with the versions of the same
/// key it replaced.
#[derive(Clone, Debug)]
struct Staged {
    /// Where in this transaction the write happened, which is how a TRUNCATE
    /// knows which staged rows it covers.
    ord: u64,
    /// The command that made it: heap's cmin for a Put, cmax for a Delete.
    cid: CommandId,
    op: Op,
    /// What earlier commands of this transaction wrote at this key, oldest
    /// first. A scan whose command cannot see the newest reads back through
    /// them, as a heap scan still sees the version a later command deleted.
    earlier: Vec<(u64, CommandId, Op)>,
}

impl Staged {
    /// The version a command reading at `curcid` sees, with its position.
    fn seen_at(&self, curcid: CommandId) -> Option<(u64, &Op)> {
        if seen_by(self.cid, curcid) {
            return Some((self.ord, &self.op));
        }
        self.earlier
            .iter()
            .rev()
            .find(|(_, cid, _)| seen_by(*cid, curcid))
            .map(|(ord, _, op)| (*ord, op))
    }

    /// Replaces `older`, keeping it as the version an earlier command sees.
    fn over(mut self, older: Staged) -> Staged {
        let mut earlier = older.earlier;
        // Two writes by one command are one version: the later.
        if older.cid != self.cid {
            earlier.push((older.ord, older.cid, older.op));
        }
        earlier.append(&mut self.earlier);
        self.earlier = earlier;
        self
    }
}

thread_local! {
    /// This backend's uncommitted writes, outermost frame first. The
    /// process-global memtable would let one session read another's; a stack so
    /// ROLLBACK TO SAVEPOINT can discard part of it.
    static PENDING: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };

    static XACT_REGISTERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

        static MY_COMMIT_SEQ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };

    static XACT_SNAPSHOT: std::cell::Cell<u64> = const { std::cell::Cell::new(u64::MAX) };

    /// One read view per snapshot this transaction reads at, keyed by the
    /// snapshot's commit number. A view answers a read at a number at or
    /// below the one it was taken with the same way for ever, so one taken
    /// with the snapshot serves every row the snapshot fetches; per-row
    /// trips through the Db lock -- and the S3 GETs a cold fetch makes under
    /// it -- are what this replaces. Cleared at transaction end.
    static SNAPSHOT_VIEWS: RefCell<BTreeMap<u64, Rc<::objkv::db::View>>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Which table each objkv index belongs to, learned as they are used: the
/// collector needs it and cannot read pg_index while holding the storage lock.
/// An untouched index's entries are left alone.
static INDEX_TABLES: Mutex<Option<BTreeMap<u32, u32>>> = Mutex::new(None);

pub(crate) fn note_index_table(index: ::types_core::Oid, relid: ::types_core::Oid) {
    let mut g = INDEX_TABLES.lock().unwrap();
    g.get_or_insert_with(BTreeMap::new).insert(index, relid);
}

fn index_tables() -> BTreeMap<u32, u32> {
    INDEX_TABLES.lock().unwrap().clone().unwrap_or_default()
}

/// The oldest commit each backend is reading at; the collector must not
/// discard history one of these can ask for.
static IN_USE: Mutex<Option<BTreeMap<u64, u64>>> = Mutex::new(None);

fn my_slot() -> u64 {
    let t = std::thread::current().id();
    // ThreadId has no stable numeric form; a collision only makes the horizon
    // more conservative.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

fn note_in_use(seq: u64) {
    // Armed here, not only where writes are: a read-only session takes no other
    // path, and its leftover read point froze collection for good.
    ensure_xact_callback();
    let mut g = IN_USE.lock().unwrap();
    let m = g.get_or_insert_with(BTreeMap::new);
    let e = m.entry(my_slot()).or_insert(u64::MAX);
    *e = (*e).min(seq);
}

fn release_in_use() {
    if let Some(m) = IN_USE.lock().unwrap().as_mut() {
        m.remove(&my_slot());
    }
}

fn oldest_in_use() -> u64 {
    IN_USE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.values().copied().min())
        .unwrap_or(u64::MAX)
}

/// Where objkv stands, republished so [`note_snapshot`] need not open the Db.
static SEQ_NOW: AtomicU64 = AtomicU64::new(0);
static DB_OPEN: AtomicBool = AtomicBool::new(false);

/// Stamps a snapshot with where objkv stands when it is taken, so a commit a
/// millisecond later cannot pass for one it should see; deciding at first read
/// makes every commit in between visible.
fn note_snapshot(sn: &SnapshotData<'static>) {
    if DB_OPEN.load(Ordering::Relaxed) {
        sn.am_commit_seq.set(SEQ_NOW.load(Ordering::Relaxed));
    }
}

thread_local! {
    /// The command id of the snapshot `snapshot_seq` last resolved, for
    /// `objkv_index::load_scan`: its caller resolves the scan's snapshot to a
    /// commit number with `snapshot_seq` and hands over only the number.
    static LAST_SNAPSHOT_CID: std::cell::Cell<CommandId> = const { std::cell::Cell::new(InvalidCommandId) };
}

/// The command a snapshot reads as: heap's `curcid`. Only an MVCC snapshot
/// draws the line; SnapshotSelf, SnapshotDirty and SnapshotAny see the current
/// command's own writes, as they do on the heap, and so does a read with no
/// snapshot at all.
pub fn snapshot_cid(snapshot: Option<&SnapshotData<'_>>) -> CommandId {
    match snapshot {
        Some(sn) if ::types_snapshot::IsMVCCSnapshot(sn) => sn.curcid.get(),
        _ => InvalidCommandId,
    }
}

/// The command id of the snapshot `snapshot_seq` last resolved.
pub fn last_snapshot_cid() -> CommandId {
    LAST_SNAPSHOT_CID.with(|c| c.get())
}

pub fn snapshot_seq(snapshot: Option<&SnapshotData<'_>>) -> PgResult<u64> {
    LAST_SNAPSHOT_CID.with(|c| c.set(snapshot_cid(snapshot)));
    let Some(sn) = snapshot else {
        return Ok(::objkv::key::LATEST);
    };
    if let Some(forced) = time_travel_seq() {
        // A read into the past pins history as a present one does: the
        // collector must not fold or drop runs this scan is still fetching
        // from the bucket. Writes are refused while the setting is on
        // (`refuse_writes_into_the_past`); the validation point is recorded
        // anyway, for a transaction that reads here and resets the setting
        // before it writes.
        XACT_SNAPSHOT.set(XACT_SNAPSHOT.get().min(forced));
        note_in_use(forced);
        return Ok(forced);
    }
    let seq = match sn.am_commit_seq.get() {
        0 => {
            // The number and the view under one acquisition: the view is what
            // every read at this snapshot goes through from here on.
            let (seq, v) = with_db(|db| (db.current_seq(), db.view()))?;
            sn.am_commit_seq.set(seq);
            remember_view(seq, v);
            seq
        }
        seq => seq,
    };
    // What writes validate against, and what collection must not go under.
    XACT_SNAPSHOT.set(XACT_SNAPSHOT.get().min(seq));
    note_in_use(seq);
    Ok(seq)
}

pub fn init_seams() {
    ::snapmgr::tap_snapshot_taken::install(note_snapshot);
}

/// A clean exit: lands whatever asynchronous commits are still queued, then
/// gives the single-writer lease back so the next open -- on this host or
/// another -- claims at once instead of waiting out the lease TTL. The
/// object is the commit, so nothing else needs publishing on the way out.
fn release_lease_at_exit(_code: i32, _arg: usize) {
    if !DB_OPEN.load(Ordering::Relaxed) {
        return;
    }
    // Acknowledged-but-unwritten commits go first: after the release every
    // write is refused, and a client was already told they had committed.
    drain_writes();
    if let Ok(Err(e)) = with_db_raw(|db| db.release_lease()) {
        eprintln!("objkv: could not release the lease at exit: {e}");
    }
}

/// A backend that leaves without a transaction end must not pin the horizon.
fn release_horizon_at_backend_exit(_code: i32, _arg: usize) {
    release_in_use();
}

static EXIT_RELEASE_ARMED: AtomicBool = AtomicBool::new(false);

/// Per backend: give the collection horizon back when the thread leaves.
/// Once per process: give the lease back when the process leaves. The lease
/// is shared by every backend, so it must not go with the first client that
/// disconnects; `on_process_exit` fires on the postmaster's own exit.
fn arm_exit_release() {
    if ::ipc_seams::on_proc_exit::is_installed() {
        ::ipc_seams::on_proc_exit::call(release_horizon_at_backend_exit, 0);
    }
    if ::ipc_seams::on_process_exit::is_installed()
        && !EXIT_RELEASE_ARMED.swap(true, Ordering::AcqRel)
    {
        ::ipc_seams::on_process_exit::call(release_lease_at_exit, 0);
    }
}

/// How far back collection may reach. Held down by
/// `pgrust.objkv_retain_commits` (0 promises for ever) and by open reads.
fn collection_horizon(now: u64) -> u64 {
    let retain = ::guc_tables::vars::pgrust_objkv_retain_commits.read();
    if retain <= 0 {
        return 0;
    }
    now.saturating_sub(retain as u64).min(oldest_in_use())
}

fn time_travel_seq() -> Option<u64> {
    let v = ::guc_tables::vars::pgrust_objkv_snapshot_seq.read();
    (v > 0).then_some(v as u64)
}

/// Whether this session is reading history rather than the present.
///
/// It decides one thing: whether a read sees this transaction's own
/// uncommitted writes. It must, except when the read is deliberately of a past
/// they are not part of. This was once decided by "the snapshot is not
/// LATEST", which is true of an ordinary MVCC snapshot too -- so a transaction
/// that wrote and then read got the bucket without its own writes, and only
/// multi-statement transactions ever noticed.
pub fn reading_the_past() -> bool {
    time_travel_seq().is_some()
}

// Counts staged writes, so a TRUNCATE can tell which of them it covers.
thread_local! {
    static STAGE_ORD: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Refuses a write while `pgrust.objkv_snapshot_seq` forces a past snapshot.
/// The rows such a transaction reads are not the present ones, so a write
/// decided from them is a lost update: the snapshot it would be validated
/// against is one nobody else's commits are measured from. Called by every
/// fallible write path and again at pre-commit for the infallible ones.
pub(crate) fn refuse_writes_into_the_past() -> PgResult<()> {
    let Some(seq) = time_travel_seq() else {
        return Ok(());
    };
    Err(Box::new(
        PgError::error("cannot write objkv tables while reading a past snapshot".to_string())
            .with_detail(format!(
                "Writes are not allowed while pgrust.objkv_snapshot_seq (currently {seq}) forces a past snapshot."
            ))
            .with_hint("RESET pgrust.objkv_snapshot_seq to write to the present.".to_string())
            .with_sqlstate(::types_error::ERRCODE_READ_ONLY_SQL_TRANSACTION),
    ))
}

/// Stages a write of the current command, stamped with its id. The id is
/// marked used, as heap_insert marks it, so CommandCounterIncrement advances
/// past it and the next statement sees the write.
pub(crate) fn stage(key: Vec<u8>, op: Op) -> PgResult<()> {
    // heapam's accessor. The error is a parallel worker's, which never writes.
    let cid = ::xact_seams::get_current_command_id::call(true)?;
    ensure_xact_callback();
    stage_in(::xact::GetCurrentSubTransactionId(), key, op, cid);
    Ok(())
}

/// Stages a rewrite of a row where it stands, visible as heap's in-place
/// update is: to every command if the row is in the store, and from the same
/// command as the version it rewrites if this transaction staged that.
fn stage_in_place(key: Vec<u8>, op: Op) {
    ensure_xact_callback();
    let cid = staged_stamp(&key).unwrap_or(SEEN_BY_ALL);
    stage_in(::xact::GetCurrentSubTransactionId(), key, op, cid);
}

/// Stages a write on behalf of subtransaction `subid`: the top frame if it
/// is that subtransaction's, a new one on top otherwise.
fn stage_in(subid: SubTransactionId, key: Vec<u8>, op: Op, cid: CommandId) {
    let ord = STAGE_ORD.with(|c| {
        let n = c.get() + 1;
        c.set(n);
        n
    });
    PENDING.with(|p| {
        let mut stack = p.borrow_mut();
        if stack.last().map(|f| f.subid) != Some(subid) {
            stack.push(Frame { subid, writes: BTreeMap::new() });
        }
        let writes = &mut stack.last_mut().unwrap().writes;
        let write = Staged { ord, cid, op, earlier: Vec::new() };
        let write = match writes.remove(&key) {
            Some(older) => write.over(older),
            None => write,
        };
        writes.insert(key, write);
    });
}

/// Where the transaction's writes have got to, for a TRUNCATE to record.
pub(crate) fn stage_mark() -> u64 {
    STAGE_ORD.with(|c| c.get())
}

/// Records that this transaction decided something from the bucket at `seq`.
/// An insert-only transaction never takes an objkv snapshot, so without this
/// two inserts of one unique value both commit.
pub(crate) fn observe_read_at(seq: u64) {
    XACT_SNAPSHOT.set(XACT_SNAPSHOT.get().min(seq));
    note_in_use(seq);
}

/// What this transaction has staged for `key`, whichever command wrote it. A
/// uniqueness check needs it: two rows with one value write the same index
/// key, and the second would overwrite the first -- one entry, no error.
pub(crate) fn staged_op(key: &[u8]) -> Option<Op> {
    staged_seen_by(key, InvalidCommandId).map(|(_, op)| op)
}

/// The staged version of `key` a command reading at `curcid` sees, innermost
/// frame first. A frame's write replaced the one outside it, so a frame with
/// nothing visible passes the question outward.
fn staged_seen_by(key: &[u8], curcid: CommandId) -> Option<(u64, Op)> {
    PENDING.with(|p| {
        p.borrow().iter().rev().find_map(|f| {
            f.writes.get(key).and_then(|w| w.seen_at(curcid)).map(|(ord, op)| (ord, op.clone()))
        })
    })
}

/// The command that made the newest staged write of `key`, if any.
fn staged_stamp(key: &[u8]) -> Option<CommandId> {
    PENDING.with(|p| p.borrow().iter().rev().find_map(|f| f.writes.get(key).map(|w| w.cid)))
}

/// This transaction's staged writes in `[lo, hi)` as a command reading at
/// `curcid` sees them, one version per key.
pub(crate) fn staged_range(lo: &[u8], hi: &[u8], curcid: CommandId) -> BTreeMap<Vec<u8>, (u64, Op)> {
    PENDING.with(|p| {
        let mut out = BTreeMap::new();
        for f in p.borrow().iter() {
            for (k, w) in f.writes.range(lo.to_vec()..hi.to_vec()) {
                // Nothing visible in this frame leaves the outer frame's version.
                if let Some((ord, op)) = w.seen_at(curcid) {
                    out.insert(k.clone(), (ord, op.clone()));
                }
            }
        }
        out
    })
}

/// Lays this transaction's staged writes in `[lo, hi)` over `merged`, as a
/// command reading at `curcid` sees them. `since` is where the relation's
/// last TRUNCATE in this transaction left the write counter.
pub(crate) fn overlay_staged(
    merged: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    lo: &[u8],
    hi: &[u8],
    since: u64,
    curcid: CommandId,
) {
    for (k, (ord, op)) in staged_range(lo, hi, curcid) {
        // Written before a TRUNCATE this transaction ran: covered by it.
        if ord <= since {
            merged.remove(&k);
            continue;
        }
        match op {
            Op::Put(v) => {
                merged.insert(k, v);
            }
            Op::Delete => {
                merged.remove(&k);
            }
        }
    }
}

fn flatten_pending() -> BTreeMap<Vec<u8>, Op> {
    // Writes a TRUNCATE covered are dropped here, not when it ran, since until
    // now a savepoint could bring them back. Everything a transaction writes
    // shares one sequence number, so a row from before the truncate would
    // otherwise look like one from after it.
    let covered: Vec<(Vec<Vec<u8>>, u64)> = EMPTIED.with(|e| {
        e.borrow()
            .iter()
            .map(|(marker, since)| (covered_prefixes(marker), *since))
            .collect()
    });
    PENDING.with(|p| {
        let stack = std::mem::take(&mut *p.borrow_mut());
        let mut out = BTreeMap::new();
        for f in stack {
            for (k, Staged { ord, op, .. }) in f.writes {
                let dropped = covered.iter().any(|(prefixes, since)| {
                    ord <= *since && prefixes.iter().any(|pre| k.starts_with(pre))
                });
                if !dropped {
                    out.insert(k, op);
                }
            }
        }
        out
    })
}

/// What a truncation covers: rows, and any index's entries. No catalog.
fn covered_prefixes(marker: &[u8]) -> Vec<Vec<u8>> {
    // t/{db:08x}/{oid:08x}
    let mut parts = marker.split(|&b| b == b'/');
    let (Some(b"t"), Some(db), Some(oid)) = (parts.next(), parts.next(), parts.next()) else {
        return Vec::new();
    };
    let (db, oid) = (String::from_utf8_lossy(db), String::from_utf8_lossy(oid));
    vec![
        format!("{db}/{oid}/").into_bytes(),
        format!("{db}/u/{oid}/").into_bytes(),
        format!("{db}/i/{oid}/").into_bytes(),
    ]
}

fn ensure_xact_callback() {
    XACT_REGISTERED.with(|c| {
        if !c.get() {
            ::xact::RegisterXactCallback(objkv_xact_callback, Datum::null());
            ::xact::RegisterSubXactCallback(objkv_subxact_callback, Datum::null());
            arm_exit_release();
            c.set(true);
        }
    });
}

fn objkv_subxact_callback(
    event: ::types_core::xact::SubXactEvent,
    my_subid: SubTransactionId,
    parent_subid: SubTransactionId,
    _arg: Datum,
) -> PgResult<()> {
    use ::types_core::xact::SubXactEvent::*;
    match event {
        SUBXACT_EVENT_START_SUB | SUBXACT_EVENT_PRE_COMMIT_SUB => {}
        SUBXACT_EVENT_COMMIT_SUB => PENDING.with(|p| {
            let mut stack = p.borrow_mut();
            while stack.last().is_some_and(|f| f.subid == my_subid) {
                let f = stack.pop().unwrap();
                // Into the parent's own frame and no other: a parent savepoint
                // that wrote nothing has no frame, and the one below belongs
                // to an ancestor. Merged there, the released writes would
                // survive a ROLLBACK TO the parent.
                match stack.last_mut() {
                    Some(parent) if parent.subid == parent_subid => {
                        for (k, w) in f.writes {
                            let w = match parent.writes.remove(&k) {
                                Some(older) => w.over(older),
                                None => w,
                            };
                            parent.writes.insert(k, w);
                        }
                    }
                    _ => stack.push(Frame { subid: parent_subid, writes: f.writes }),
                }
            }
        }),
        SUBXACT_EVENT_ABORT_SUB => {
            PENDING.with(|p| {
                let mut stack = p.borrow_mut();
                while stack.last().is_some_and(|f| f.subid >= my_subid) {
                    stack.pop();
                }
            });
            // A truncate in the rolled-back subtransaction goes with it: its
            // marker was one of the writes just dropped.
            EMPTIED.with(|e| {
                e.borrow_mut()
                    .retain(|k, _| PENDING.with(|p| p.borrow().iter().any(|f| f.writes.contains_key(k))));
            });
        }
    }
    Ok(())
}

fn objkv_xact_callback(
    event: ::types_core::xact::XactEvent,
    _arg: Datum,
) -> PgResult<()> {
    use ::types_core::xact::XactEvent::*;
    match event {
        // PRE_COMMIT: the last point a failed PUT can still abort the transaction.
        XACT_EVENT_PRE_COMMIT | XACT_EVENT_PARALLEL_PRE_COMMIT => at_pre_commit(),
        XACT_EVENT_ABORT | XACT_EVENT_PARALLEL_ABORT => {
            // An abort after pre-commit leaves an object nothing stands behind.
            let seq = MY_COMMIT_SEQ.replace(0);
            if seq != 0 {
                discard_commit(seq)?;
            }
            discard_pending();
            forget_snapshots();
            forget_emptied();
            Ok(())
        }
        XACT_EVENT_COMMIT | XACT_EVENT_PARALLEL_COMMIT => {
            let seq = MY_COMMIT_SEQ.replace(0);
            if seq != 0 {
                with_db(|db| db.mark_confirmed(seq))?;
            }
            forget_snapshots();
            forget_emptied();
            Ok(())
        }
        XACT_EVENT_PRE_PREPARE | XACT_EVENT_PREPARE => {
            if PENDING.with(|p| p.borrow().iter().all(|f| f.writes.is_empty())) {
                Ok(())
            } else {
                Err(unsupported("PREPARE TRANSACTION"))
            }
        }
    }
}

/// One thread writes commit objects; everything else queues behind it.
///
/// A backend at pre-commit numbers and validates its writes under the storage
/// lock, then either waits for the writer to report its ticket durable or --
/// with `pgrust.objkv_async_commit` on -- carries on. The writer takes all
/// that is queued as one object, PUTs it with no lock held, and reports back.
/// The lock and condition variable here carry only the wake-ups; the queue
/// itself is in the [`Db`].
static SIGNAL: (Mutex<u64>, Condvar) = (Mutex::new(0), Condvar::new());
static WRITER: OnceLock<()> = OnceLock::new();
/// One thread per object that may be in flight. Each takes whatever is queued
/// when it wakes, so under load the flights pipeline instead of queueing
/// behind one round trip.
const WRITER_THREADS: usize = ::objkv::db::MAX_IN_FLIGHT;

fn signal() {
    let mut g = SIGNAL.0.lock().unwrap_or_else(|e| e.into_inner());
    *g += 1;
    SIGNAL.1.notify_all();
}

fn ensure_writer() {
    WRITER.get_or_init(|| {
        for i in 0..WRITER_THREADS {
            std::thread::Builder::new()
                .name(format!("objkv-writer-{i}"))
                .spawn(writer_loop)
                .expect("spawning an objkv writer thread");
        }
        std::thread::Builder::new()
            .name("objkv-compactor".into())
            .spawn(compactor_loop)
            .expect("spawning the objkv compactor thread");
    });
}

/// The compactor's wake-up, and the collection horizon the requesters have
/// asked for: the highest wins, and a request with none leaves it be.
static COMPACT: (Mutex<u64>, Condvar) = (Mutex::new(0), Condvar::new());
static HORIZON_WANTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn request_compaction(horizon: u64) {
    HORIZON_WANTED.fetch_max(horizon, Ordering::Relaxed);
    let mut g = COMPACT.0.lock().unwrap_or_else(|e| e.into_inner());
    *g += 1;
    COMPACT.1.notify_all();
}

/// Folds commits into runs whenever asked, with every GET, PUT and DELETE
/// made with no lock held: the plan and the swap are the only steps under
/// it, and both are memory-only. A fold that fails is logged and retried
/// on the next request; the data is already durable in its commit objects.
fn compactor_loop() {
    loop {
        {
            let g = COMPACT.0.lock().unwrap_or_else(|e| e.into_inner());
            let _ = COMPACT.1.wait_timeout(g, std::time::Duration::from_secs(1));
        }
        let horizon = HORIZON_WANTED.swap(0, Ordering::Relaxed);
        loop {
            let plan = match with_db_raw(|db| db.needs_compaction().then(|| db.fold_plan()).flatten()) {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    eprintln!("objkv compactor: {e}");
                    break;
                }
            };
            let tables = index_tables();
            let store = store();
            let folded = match ::objkv::db::build_fold(&plan, horizon, &tables)
                .and_then(|f| ::objkv::db::put_fold(&store, &f).map(|_| f))
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("objkv compactor: fold failed, commit chain keeps growing: {e}");
                    break;
                }
            };
            let sweep = match with_db_raw(|db| db.apply_fold(plan, &folded, horizon)) {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    eprintln!("objkv compactor: could not open the run it wrote: {e}");
                    break;
                }
                Err(e) => {
                    eprintln!("objkv compactor: {e}");
                    break;
                }
            };
            let result = ::objkv::db::execute_sweep(&store, sweep);
            let _ = with_db_raw(|db| db.sweep_done(result));
        }
    }
}

fn writer_loop() {
    const ATTEMPTS: u32 = 3;
    loop {
        let flight = {
            // Checked and waited on under the one lock, so a kick between
            // the check and the wait cannot be lost.
            let g = SIGNAL.0.lock().unwrap_or_else(|e| e.into_inner());
            match with_db_raw(|db| db.take_flight()) {
                Ok(Some(f)) => f,
                Ok(None) => {
                    let _ = SIGNAL.1.wait_timeout(g, std::time::Duration::from_secs(1));
                    continue;
                }
                Err(e) => {
                    eprintln!("objkv writer: {e}");
                    let _ = SIGNAL.1.wait_timeout(g, std::time::Duration::from_secs(1));
                    continue;
                }
            }
        };
        let mut attempt = 0;
        loop {
            attempt += 1;
            let done = match store().put_if_absent(&flight.key, &flight.bytes) {
                Ok(::objkv::s3::PutOutcome::Written) => with_db_raw(|db| db.flight_written(flight.first)).map(|_| true),
                Ok(::objkv::s3::PutOutcome::AlreadyExists) => {
                    with_db_raw(|db| db.flight_lost(&flight)).map(|r| {
                        if let Err(e) = r {
                            eprintln!("objkv writer: {e}");
                        }
                        true
                    })
                }
                Err(e) if attempt < ATTEMPTS => {
                    eprintln!("objkv writer: PUT of {} failed ({e}); retrying", flight.key);
                    std::thread::sleep(std::time::Duration::from_millis(100 * attempt as u64));
                    Ok(false)
                }
                Err(e) => with_db_raw(|db| db.flight_failed(flight.first, &e.to_string())).map(|_| true),
            };
            match done {
                Ok(true) => break,
                Ok(false) => continue,
                Err(e) => {
                    eprintln!("objkv writer: {e}");
                    break;
                }
            }
        }
        signal();
    }
}

/// Blocks until the writer has dealt with `ticket`.
fn wait_outcome(ticket: u64) -> PgResult<Outcome> {
    loop {
        let g = SIGNAL.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(o) = with_db_raw(|db| db.take_outcome(ticket))? {
            return Ok(o);
        }
        let _ = SIGNAL.1.wait_timeout(g, std::time::Duration::from_secs(1));
    }
}

/// Waits until nothing is owed to the bucket. Used on the way out, so an
/// asynchronous commit is only ever lost to a crash, never to a shutdown.
fn drain_writes() {
    loop {
        let g = SIGNAL.0.lock().unwrap_or_else(|e| e.into_inner());
        match with_db_raw(|db| db.has_unwritten()) {
            Ok(true) => {}
            _ => return,
        }
        let _ = SIGNAL.1.wait_timeout(g, std::time::Duration::from_secs(1));
    }
}

fn serialization_failure(c: &::objkv::db::Conflict) -> Box<PgError> {
    let (what, detail) = describe_conflict(c);
    Box::new(
        PgError::error(format!("could not serialize access due to concurrent update of {what}"))
            .with_detail(detail)
            .with_hint("Retry the transaction.".to_string())
            .with_sqlstate(::types_error::ERRCODE_T_R_SERIALIZATION_FAILURE),
    )
}

/// Forgets a staged commit that will never become real. If its object is or
/// may be in the bucket the discard marker for it is written here -- with no
/// lock held, so a PUT does not stall readers -- and a marker that cannot be
/// written fences the process: without it the next open would apply the
/// aborted transaction.
fn discard_commit(seq: u64) -> PgResult<()> {
    let marker = with_db_raw(|db| db.begin_discard(seq, ::objkv::db::Discard::Aborted))?;
    if let Some(m) = marker {
        match m.write(&store()) {
            Ok(()) => with_db_raw(|db| db.discard_written(m))?,
            Err(e) => with_db_raw(|db| {
                db.discard_failed(&m, &e);
            })?,
        }
    }
    Ok(())
}

fn at_pre_commit() -> PgResult<()> {
    let writes = flatten_pending();
    if writes.is_empty() {
        return Ok(());
    }
    // The paths that stage without a Result (a TRUNCATE's marker, the lift's
    // record, an index entry) are caught here instead.
    refuse_writes_into_the_past()?;
    let n = writes.len();
    // Only so a discarded object can name its transaction in the log; often 0,
    // since an objkv-only transaction writes no WAL.
    let xid = ::xact::GetCurrentTransactionIdIfAny();
    // Against the oldest snapshot read at, so a row changed since then is a
    // conflict; u64::MAX means we never read and nothing can have moved.
    let snap = XACT_SNAPSHOT.replace(u64::MAX);
    let wants_async = ::guc_tables::vars::pgrust_objkv_async_commit.read();
    let cap = ::guc_tables::vars::pgrust_objkv_async_queue.read().max(1) as usize;
    // First-committer-wins has two halves. The run half may read from the
    // bucket, so it is done here through a view with no lock held; the
    // in-memory half, and the run half again only if a fold has replaced the
    // runs since this view was taken, is done under the lock by
    // `stage_commit_checked`.
    let probe = view()?;
    let probed_base = probe.base_run_id();
    if let Some(c) = probe
        .find_run_conflict(&writes, snap)
        .map_err(|e| Box::new(PgError::error(format!("objkv: commit of {n} changes failed: {e}"))))?
    {
        return Err(serialization_failure(&c));
    }
    drop(probe);
    // Decided under the lock, with the queue as it is at that moment: an
    // asynchronous commit behind `cap` acknowledged-but-unwritten ones waits
    // like a synchronous one. That bounds what a crash can lose and what a
    // writer that cannot reach the bucket can fence, and turns a stuck
    // writer into slow commits rather than a growing queue.
    let (staged, sync) = with_db(|db| {
        let sync = !wants_async || db.async_backlog() >= cap;
        (db.stage_commit_checked(writes, xid, snap, sync, probed_base), sync)
    })?;
    let staged = staged
        .map_err(|e| Box::new(PgError::error(format!("objkv: commit of {n} changes failed: {e}"))))?;
    let (ticket, seq) = match staged {
        Ok(Some(x)) => x,
        Ok(None) => return Ok(()),
        Err(c) => return Err(serialization_failure(&c)),
    };
    MY_COMMIT_SEQ.set(seq);
    ensure_writer();
    signal();

    if sync {
        match wait_outcome(ticket)? {
            Outcome::Durable(landed) => {
                MY_COMMIT_SEQ.set(landed);
                // Fault points for the tests, here and only here: the object
                // is durable, and the client has been told nothing yet. An
                // asynchronous commit never reaches this arm, so the hooks
                // cannot fire ahead of the PUT.
                // A crash here keeps the commit, as a lost COMMIT reply does
                // under WAL. abort(), not panic!, so nothing unwinds -- as
                // kill -9 would.
                if std::env::var_os("OBJKV_FAULT_AFTER_COMMIT_PUT").is_some() {
                    eprintln!("objkv: OBJKV_FAULT_AFTER_COMMIT_PUT -- aborting after the PUT, before commit");
                    std::process::abort();
                }
                // An error here aborts the transaction: the abort path
                // writes the discard marker that keeps the object from ever
                // being applied.
                if std::env::var_os("OBJKV_FAULT_ERROR_AFTER_COMMIT_PUT").is_some() {
                    return Err(Box::new(PgError::error(
                        "objkv: OBJKV_FAULT_ERROR_AFTER_COMMIT_PUT -- failing after the PUT, before commit"
                            .to_string(),
                    )));
                }
            }
            // Reserved in the engine, produced by nothing: a lost sequence
            // race fences the process instead of re-validating.
            Outcome::Refused(c) => {
                unreachable!("objkv: Outcome::Refused is never produced ({c:?})")
            }
            // Nothing landed under either of these, so there is nothing for
            // the abort path to discard.
            Outcome::Failed(why) | Outcome::Fenced(why) => {
                MY_COMMIT_SEQ.set(0);
                return Err(Box::new(PgError::error(format!(
                    "objkv: commit of {n} changes failed: {why}"
                ))));
            }
        }
    }

    // Fold the chain into a run, or every scan replays all history. Done by
    // the compactor thread, off this backend and off the lock: the horizon
    // is decided here, where this session's retention setting and the open
    // snapshots are known.
    let (wanted, now) = with_db(|db| (db.needs_compaction(), db.current_seq()))?;
    if wanted {
        request_compaction(collection_horizon(now));
    }
    Ok(())
}

/// Names what collided: "row changed" for a duplicate key misdirects.
fn describe_conflict(c: &::objkv::db::Conflict) -> (String, String) {
    let key = String::from_utf8_lossy(&c.key).into_owned();
    let index_oid = key
        .strip_prefix("u/")
        .or_else(|| key.strip_prefix("i/"))
        .and_then(|rest| rest.split('/').next())
        .and_then(|hex| u32::from_str_radix(hex, 16).ok());
    match index_oid {
        Some(oid) => (
            format!("an index entry in objkv index {oid}"),
            format!(
                "Commit {} wrote the same entry. On a unique index this is a duplicate \
                 value inserted concurrently; the retry will report it as one.",
                c.by
            ),
        ),
        None => (
            format!("objkv row {key}"),
            format!("The row was changed by commit {}.", c.by),
        ),
    }
}

fn forget_snapshots() {
    XACT_SNAPSHOT.set(u64::MAX);
    SNAPSHOT_VIEWS.with(|v| v.borrow_mut().clear());
    release_in_use();
}

fn discard_pending() {
    PENDING.with(|p| p.borrow_mut().clear());
    MY_COMMIT_SEQ.set(0);
}

/// The store `open_store` chose. The writer and compactor threads and the
/// discard path run only once an open has succeeded, so a miss here is a
/// programming error, not a configuration one.
fn store() -> Arc<dyn Store> {
    Arc::clone(STORE.get().expect("objkv: store used before open_store chose one"))
}

/// Chooses the backing store once per process, and says which in the log.
///
/// The server has exactly one store: the object store named by
/// `OBJKV_S3_ENDPOINT`. There is no memory mode. Unit tests, which run without
/// a server, use `MemStore` directly; their tables are meant to vanish.
fn open_store() -> PgResult<Arc<dyn Store>> {
    if let Some(s) = STORE.get() {
        return Ok(Arc::clone(s));
    }
    let chosen = choose_store()?;
    // Two backends racing to open keep the first; the loser's is dropped unused.
    Ok(Arc::clone(STORE.get_or_init(|| chosen)))
}

fn choose_store() -> PgResult<Arc<dyn Store>> {
    if cfg!(test) {
        return Ok(Arc::new(MemStore::new()) as Arc<dyn Store>);
    }
    let Ok(endpoint) = std::env::var("OBJKV_S3_ENDPOINT") else {
        return Err(Box::new(
            PgError::error("objkv storage is not configured")
                .with_detail(
                    "OBJKV_S3_ENDPOINT is unset. objkv tables live in an object store and \
                     nowhere else.",
                )
                .with_hint(
                    "Set OBJKV_S3_ENDPOINT (and OBJKV_S3_BUCKET, OBJKV_S3_KEY, OBJKV_S3_SECRET).",
                )
                .with_sqlstate(::types_error::ERRCODE_CONFIG_FILE_ERROR),
        ));
    };
    let bucket = std::env::var("OBJKV_S3_BUCKET").unwrap_or_else(|_| "objkv".to_string());
    let store = object_store(&endpoint)?;
    log_store(format!("objkv: storage is the object store at {endpoint}, bucket \"{bucket}\""));
    Ok(store)
}

/// LOG, once the server's error machinery is up; unit tests have no elog.
fn log_store(msg: String) {
    if ::elog_seams::ereport_msg::is_installed() {
        let _ = ::elog_seams::ereport_msg::call(::types_error::LOG, msg, None);
    }
}

/// The object-store client.
fn object_store(endpoint: &str) -> PgResult<Arc<dyn Store>> {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let key = env("OBJKV_S3_KEY", "minioadmin");
    let secret = env("OBJKV_S3_SECRET", "minioadmin");
    let bucket = env("OBJKV_S3_BUCKET", "objkv");
    let region = env("OBJKV_S3_REGION", "us-east-1");
    let built = match std::env::var("OBJKV_S3_TOKEN") {
        Ok(tok) => {
            ::objkv::s3::Client::new_with_token(endpoint, &bucket, &region, &key, &secret, &tok)
        }
        Err(_) => ::objkv::s3::Client::new(endpoint, &bucket, &region, &key, &secret),
    };
    // A config error must not read as "your data vanished on restart".
    built.map(|c| Arc::new(c) as Arc<dyn Store>).map_err(|e| {
        Box::new(
            PgError::error(format!(
                "objkv: OBJKV_S3_ENDPOINT is set but the S3 client could not be built: {e}"
            ))
            .with_sqlstate(::types_error::ERRCODE_CONFIG_FILE_ERROR),
        )
    })
}

pub fn unsupported(what: &str) -> Box<PgError> {
    Box::new(
        PgError::error(format!("objkv does not support {what}"))
            .with_sqlstate(::types_error::ERRCODE_FEATURE_NOT_SUPPORTED),
    )
}

/// One log for the whole database: relations are namespaced by key prefix, and
/// two `Db` instances over one store would race for the same commit number.
///
/// Refuses once the bucket has been fenced: another writer took a number this
/// server had already acknowledged, so its picture of the data is not to be
/// trusted, reads included.
pub(crate) fn with_db<R>(f: impl FnOnce(&mut Db) -> R) -> PgResult<R> {
    with_db_raw(|db| {
        if db.is_fenced() {
            return Err(Box::new(PgError::error(
                "objkv: this server has lost the bucket to another writer and must be restarted"
                    .to_string(),
            )));
        }
        Ok(f(db))
    })?
}

/// A read view of the present, taken under the lock and used without it:
/// every S3 GET a read makes happens with no lock held, so a cold read never
/// holds up a commit or another reader. Reads at a snapshot go through
/// [`view_at`], which takes the lock once per snapshot rather than once per
/// read.
pub(crate) fn view() -> PgResult<::objkv::db::View> {
    with_db(|db| db.view())
}

/// The view a read at `at` goes through. `LATEST` is the present and gets a
/// fresh view; a snapshot number gets the view taken with it (or, for a
/// number stamped without one -- a snapshot taken before this backend's
/// first read, or a time-travel setting -- one taken now, which answers the
/// same: nothing at or below a decided prefix changes). One lock
/// acquisition per snapshot, however many rows it fetches.
pub(crate) fn view_at(at: u64) -> PgResult<Rc<::objkv::db::View>> {
    if at == ::objkv::key::LATEST {
        return Ok(Rc::new(view()?));
    }
    if let Some(v) = SNAPSHOT_VIEWS.with(|m| m.borrow().get(&at).cloned()) {
        return Ok(v);
    }
    let v = view()?;
    Ok(remember_view(at, v))
}

fn remember_view(seq: u64, v: ::objkv::db::View) -> Rc<::objkv::db::View> {
    let v = Rc::new(v);
    SNAPSHOT_VIEWS.with(|m| m.borrow_mut().entry(seq).or_insert(v).clone())
}

/// The same, fenced or not: for the writer, the abort path and the exit
/// path, which have to finish what they were doing either way.
pub(crate) fn with_db_raw<R>(f: impl FnOnce(&mut Db) -> R) -> PgResult<R> {
    let mut guard = DB.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        // The open reads the bucket as it is: an object is the commit once it
        // lands, and a transaction that aborted after its object landed left
        // a discard marker that outranks it. Nothing consults clog. The
        // journal under the data directory is where a marker the store would
        // not take waits for the next open on this host (objkv's `db.rs`).
        let store = open_store()?;
        let opened = match journal_dir() {
            Some(dir) => Db::open_with_journal(store, dir),
            None => {
                eprintln!("objkv: no data directory known here; opening without the pending-discard journal");
                Db::open(store)
            }
        };
        *guard = Some(
            opened.map_err(|e| Box::new(PgError::error(format!("objkv: cannot open storage: {e}"))))?,
        );
    }
    let db = guard.as_mut().unwrap();
    let r = f(db);
    SEQ_NOW.store(db.current_seq(), Ordering::Relaxed);
    DB_OPEN.store(true, Ordering::Relaxed);
    Ok(r)
}

/// `<PGDATA>/objkv`: the pending-discard journal's directory. `DataDir` is
/// per thread and set in backends; the first one seen is kept so that the
/// writer and compactor threads, which have none, open with the same journal
/// should the open fall to them.
fn journal_dir() -> Option<std::path::PathBuf> {
    static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
    if let Some(d) = DIR.get() {
        return Some(d.clone());
    }
    let base = std::path::PathBuf::from(::init_small::globals::DataDir()?);
    Some(DIR.get_or_init(|| base.join("objkv")).clone())
}

fn row_key(db: u32, relid: u32, rowid: u64) -> Vec<u8> {
    format!("{db:08x}/{relid:08x}/{rowid:016x}").into_bytes()
}

fn table_prefix(db: u32, relid: u32) -> Vec<u8> {
    format!("{db:08x}/{relid:08x}/").into_bytes()
}

fn hi_of(prefix: &[u8]) -> Vec<u8> {
    let mut hi = prefix.to_vec();
    hi.push(0xff);
    hi
}

/// Where "this relation was emptied" is recorded. `t` is not a hex digit, so
/// these can never be mistaken for a row or an index entry.
pub fn empty_marker_key(db: u32, oid: u32) -> Vec<u8> {
    format!("t/{db:08x}/{oid:08x}").into_bytes()
}

// Which of this transaction's writes a TRUNCATE it ran covers. Removing them
// outright would defeat a rollback to a savepoint, so it records where the
// writes had got to and reads skip the earlier ones.
thread_local! {
    static EMPTIED: RefCell<BTreeMap<Vec<u8>, u64>> = const { RefCell::new(BTreeMap::new()) };
}

/// The line below which this transaction's own staged writes for `key` are
/// covered by a truncate it performed.
fn staged_empty_mark(marker: &[u8]) -> u64 {
    EMPTIED.with(|e| e.borrow().get(marker).copied().unwrap_or(0))
}

/// Empties a relation as of now: one small object, not a tombstone per row.
pub fn empty_relation(db: u32, oid: u32) -> PgResult<()> {
    let key = empty_marker_key(db, oid);
    stage(key.clone(), Op::Put(Vec::new()))?;
    EMPTIED.with(|e| {
        e.borrow_mut().insert(key, stage_mark());
    });
    Ok(())
}

pub(crate) fn forget_emptied() {
    EMPTIED.with(|e| e.borrow_mut().clear());
    STAGE_ORD.with(|c| c.set(0));
}

/// Where this transaction's own writes for a relation were covered by a
/// TRUNCATE it ran; 0 if it ran none.
pub fn staged_empty_mark_for(db: u32, oid: u32) -> u64 {
    staged_empty_mark(&empty_marker_key(db, oid))
}

/// The commit at or below `at` where this relation was last emptied.
pub fn emptied_at(db: u32, oid: u32, at: u64) -> PgResult<Option<u64>> {
    let key = empty_marker_key(db, oid);
    view_at(at)?.emptied_at(&key, at)
        .map_err(|e| Box::new(PgError::error(format!("objkv: {e}"))))
}

/// Which database's key space a relation lives in. Oids are unique within a
/// database, not a cluster -- CREATE DATABASE copies catalog rows keeping
/// them -- so without this two databases' tables share rows. Shared: scope 0.
pub fn scope(rel: &Relation<'_>) -> u32 {
    if rel.rd_rel.relisshared {
        0
    } else {
        ::init_small::globals::MyDatabaseId()
    }
}

fn rowid_from_key(key: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(key).ok()?;
    u64::from_str_radix(s.rsplit('/').next()?, 16).ok()
}

// --- Synthetic TIDs ---------------------------------------------------------
//
// Postgres addresses tuples as (block, offset) and entries store that pair.
// There are no blocks, so a row id splits across the two: a block number and a
// 1-based offset, since zero is invalid.
//
// The block holds as many rows as a real page could. Wider would waste less of
// the block number, but a bitmap -- the structure that lets one query combine
// two indexes -- rejects any offset a heap page could not have produced. None
// of this reaches the bucket: keys carry the row id itself.

pub const ROWS_PER_BLOCK: u64 = ::types_storage::bufpage::MaxHeapTuplesPerPage as u64;
pub const MAX_ROWID: u64 = (u32::MAX as u64) * ROWS_PER_BLOCK + (ROWS_PER_BLOCK - 1);

pub fn tid_of(rowid: u64) -> ItemPointerData {
    debug_assert!(rowid <= MAX_ROWID);
    let mut tid = ItemPointerData::invalid();
    ItemPointerSet(
        &mut tid,
        (rowid / ROWS_PER_BLOCK) as u32,
        ((rowid % ROWS_PER_BLOCK) + 1) as u16,
    );
    tid
}

pub fn rowid_of(tid: &ItemPointerData) -> u64 {
    let block = ItemPointerGetBlockNumber(tid) as u64;
    let offset = ItemPointerGetOffsetNumber(tid) as u64;
    block * ROWS_PER_BLOCK + offset.saturating_sub(1)
}

// --- Row images -------------------------------------------------------------
//
// A row is its heap-tuple image, which is what makes every column type work.
// The image has to stand on its own. objkv has no TOAST table, so a datum that
// is a pointer into some heap relation's toast table would dangle the moment
// that table is vacuumed, and would point at nothing on a machine restored
// from the bucket. Every out-of-line or compressed varlena is therefore
// flattened before the tuple is formed, and a row too large once flat is
// refused, never cut.

/// The most bytes one row image may take: PG's MaxAllocSize, which bounds any
/// single datum. A row past it could not be palloc'd back into a tuple.
pub const MAX_ROW_BYTES: usize = 0x3fff_ffff;

pub fn encode_row<'mcx>(
    mcx: Mcx<'mcx>,
    desc: &TupleDescData<'_>,
    values: &[Datum],
    isnull: &[bool],
) -> PgResult<Vec<u8>> {
    let flat = flatten_varlenas(mcx, desc, values, isnull)?;
    let values = flat.as_deref().unwrap_or(values);
    let tuple = ::heaptuple::heap_form_tuple(mcx, desc, values, isnull)?;
    row_image(tuple.image())
}

/// Detoasted, decompressed copies of the varlena datums that need it, in a
/// fresh value array; `None` when every datum is already inline and plain.
fn flatten_varlenas<'mcx>(
    mcx: Mcx<'mcx>,
    desc: &TupleDescData<'_>,
    values: &[Datum],
    isnull: &[bool],
) -> PgResult<Option<Vec<Datum>>> {
    let natts = desc.natts as usize;
    let mut out: Option<Vec<Datum>> = None;
    for i in 0..natts {
        let att = &desc.compact_attrs[i];
        if isnull[i] || att.attisdropped || att.attlen != -1 {
            continue;
        }
        let p = values[i].as_usize() as *const u8;
        if !varatt_is_external_or_compressed(p) {
            continue;
        }
        // SAFETY: a non-NULL varlena datum whose header describes its own size.
        let raw = unsafe { core::slice::from_raw_parts(p, varsize_any(p)) };
        let flat = ::detoast_seams::detoast_attr::call(mcx, raw)?;
        out.get_or_insert_with(|| values[..natts].to_vec())[i] =
            Datum::from_usize(flat.leak().as_ptr() as usize);
    }
    Ok(out)
}

/// VARATT_IS_EXTERNAL || VARATT_IS_COMPRESSED, off the first header byte. A
/// short (1B) header is inline and self-contained and is left as it is.
fn varatt_is_external_or_compressed(p: *const u8) -> bool {
    // SAFETY: p addresses a live varlena header.
    let b0 = unsafe { *p };
    b0 == 0x01 || (b0 & 0x03) == 0x02
}

/// VARSIZE_ANY: the bytes a varlena occupies in whatever form it is in.
fn varsize_any(p: *const u8) -> usize {
    // SAFETY: p addresses a live varlena header.
    unsafe {
        let b0 = *p;
        if b0 == 0x01 {
            2 + match *p.add(1) {
                1 | 2 | 3 => 8,
                18 => 16,
                other => panic!("unrecognized TOAST vartag {other}"),
            }
        } else if b0 & 0x01 != 0 {
            (b0 as usize >> 1) & 0x7f
        } else {
            let w = u32::from_ne_bytes(
                core::slice::from_raw_parts(p, 4).try_into().expect("4 bytes"),
            );
            (w >> 2) as usize
        }
    }
}

/// The image as stored, once it is known to fit.
fn row_image(image: &[u8]) -> PgResult<Vec<u8>> {
    if image.len() > MAX_ROW_BYTES {
        return Err(row_too_large(image.len()));
    }
    Ok(image.to_vec())
}

fn row_too_large(len: usize) -> Box<PgError> {
    Box::new(
        PgError::error(format!(
            "objkv: row size {len} bytes exceeds maximum {MAX_ROW_BYTES}"
        ))
        .with_detail(
            "objkv has no TOAST table: every value is stored inline in its row, with \
             out-of-line and compressed values flattened first.",
        )
        .with_hint("Store the large value in a heap table, or split it across rows.")
        .with_sqlstate(::types_error::ERRCODE_PROGRAM_LIMIT_EXCEEDED),
    )
}

/// A formed catalog tuple's bytes, flattened first when a column is out of
/// line: the catalog path forms its tuple with whatever datums it was handed,
/// and one copied from a heap-era row may still point into a toast table.
fn catalog_image(rel: &Relation<'_>, tup: &HeapTupleData<'_>) -> PgResult<Vec<u8>> {
    if tup.has_external() {
        let cx = ::mcx::MemoryContext::new("objkv flatten catalog row");
        let desc = Rc::clone(&rel.rd_att);
        let natts = desc.natts as usize;
        let mut values = vec![Datum::from_usize(0); natts];
        let mut isnull = vec![true; natts];
        ::types_tuple::heap_deform_tuple(tup, &desc, &mut values, &mut isnull);
        return encode_row(cx.mcx(), &desc, &values, &isnull);
    }
    // SAFETY: a formed catalog tuple whose header is live for t_len bytes.
    row_image(unsafe { core::slice::from_raw_parts(tup.header_ptr(), tup.t_len as usize) })
}

pub fn store_image<'mcx>(
    mcx: Mcx<'mcx>,
    slot: &mut SlotData<'mcx>,
    image: &[u8],
    tid: ItemPointerData,
) -> PgResult<()> {
    let mut tuple = ::heaptuple::HeapTuple::alloc_zeroed(mcx, image.len())?;
    tuple.image_mut().copy_from_slice(image);
    tuple.as_tuple_mut().t_self = tid;
    ::exectuples::exec_store_heap_tuple_owned(slot, mcx, tuple);
    Ok(())
}

/// A block of object ids from the bucket; ordinary clusters use the WAL.
/// Needs only the store, not the `Db`, so its LIST and PUT hold no lock
/// that a reader or a commit could be waiting on.
pub fn claim_oid_block(want: u32, prefetch: u32) -> PgResult<u32> {
    let store = open_store()?;
    ::objkv::db::claim_oid_block(&store, want, prefetch)
        .map_err(|e| Box::new(PgError::error(format!("objkv: cannot claim object ids: {e}"))))
}

pub fn insert_row(db: u32, relid: u32, image: Vec<u8>) -> PgResult<u64> {
    // Before a row id is taken or the stats move: a refused insert leaves nothing behind.
    refuse_writes_into_the_past()?;
    // Seeded from the highest *live* row id, so a restart (or a TRUNCATE) does
    // reuse the ids of rows deleted at the top of the table. Versions are
    // stamped by commit number, so time-travel reads are unaffected; an index
    // entry that was never retired for such a dead row, however, then names a
    // live one. Taking the id and advancing it is one acquisition: a separate
    // read and write-back let two backends get the same id, and the later Put
    // replaced the earlier row with both clients told they had succeeded.
    // 159 of 160.
    let seeded = NEXT_ROW
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&(db, relid)).copied());
    let scanned = match seeded {
        Some(_) => None,
        None => Some(
            scan_rows(db, relid, ::objkv::key::LATEST)?
                .iter()
                .map(|(id, _)| *id)
                .max()
                .map_or(0, |m| m + 1),
        ),
    };
    let rowid = {
        let mut guard = NEXT_ROW.lock().unwrap_or_else(|e| e.into_inner());
        let map = guard.get_or_insert_with(HashMap::new);
        let next = map.entry((db, relid)).or_insert_with(|| scanned.unwrap_or(0));
        let id = *next;
        *next = id + 1;
        id
    };
    add_stats(db, relid, image.len() as i64, 1);
    stage(row_key(db, relid, rowid), Op::Put(image))?;
    Ok(rowid)
}

fn add_stats(db: u32, relid: u32, byte_delta: i64, row_delta: i64) {
    fn apply(cur: u64, delta: i64) -> u64 {
        if delta >= 0 {
            cur.saturating_add(delta as u64)
        } else {
            cur.saturating_sub(delta.unsigned_abs())
        }
    }
    let mut guard = REL_STATS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let (b, r) = map.get(&(db, relid)).copied().unwrap_or((0, 0));
    map.insert((db, relid), (apply(b, byte_delta), apply(r, row_delta)));
}

/// Seeded by one scan, then tracked incrementally. Drifts: for the planner.
pub fn relation_stats(db: u32, relid: u32) -> PgResult<(u64, u64)> {
    if let Some(s) = REL_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&(db, relid)).copied())
    {
        return Ok(s);
    }
    let rows = scan_rows(db, relid, ::objkv::key::LATEST)?;
    let stats = (rows.iter().map(|(_, v)| v.len() as u64).sum(), rows.len() as u64);
    REL_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert((db, relid), stats);
    Ok(stats)
}

pub fn relation_bytes(db: u32, relid: u32) -> PgResult<u64> {
    Ok(relation_stats(db, relid)?.0)
}

/// One raw key/value: the lift's records, which are not rows but must land in
/// the same commit object as the rows they describe. Seen by every command:
/// nothing reads a record through a snapshot (`key_exists` sees every staged
/// write), and the lift's row inserts are what mark the command used.
pub fn stage_raw(key: Vec<u8>, value: Vec<u8>) {
    ensure_xact_callback();
    stage_in(::xact::GetCurrentSubTransactionId(), key, Op::Put(value), SEEN_BY_ALL);
}

pub fn key_exists(key: &[u8]) -> PgResult<bool> {
    if let Some(op) = staged_op(key) {
        return Ok(matches!(op, Op::Put(_)));
    }
    let found = view()?.get(key)
        .map_err(|e| Box::new(PgError::error(format!("objkv: read failed: {e}"))))?;
    Ok(found.is_some())
}

/// Nothing to publish: an object is the commit once it lands, and nothing
/// vouches for it afterwards, so the lift's catalogs are as durable as their
/// commit object. Kept for the lift, which still calls it after its last
/// commit; always reports that nothing was written.
pub fn publish_watermark() -> PgResult<bool> {
    with_db(|db| db.flush_watermark())?
        .map_err(|e| Box::new(PgError::error(format!("objkv: cannot publish watermark: {e}"))))
}

/// The lift's access-method oids, before any catalog is opened: in bucket mode
/// pg_am is itself an objkv relation, so asking it is circular.
pub fn register_lifted_ams() {
    for oid in lifted_am_oids("am=") {
        ::tableam_vocab::register_objkv_table_am(oid);
    }
}

/// The oids a lift recorded under one field name; no catalog is reachable.
pub fn lifted_am_oids(field: &'static str) -> Vec<u32> {
    let Ok(records) = lift_records() else { return Vec::new() };
    records
        .iter()
        .flat_map(|r| r.split_whitespace())
        .filter_map(|f| f.strip_prefix(field)?.parse::<u32>().ok())
        .filter(|&oid| oid != 0)
        .collect()
}

/// Every `lift/...` record, as written text. Nobody else writes there.
pub fn lift_records() -> PgResult<Vec<String>> {
    Ok(lift_records_keyed()?.into_iter().map(|(_, v)| v).collect())
}

/// The same records with their keys, for a message that can name the scope.
pub fn lift_records_keyed() -> PgResult<Vec<(String, String)>> {
    let found = view()?.scan_prefix_at(b"lift/", ::objkv::key::LATEST)
        .map_err(|e| Box::new(PgError::error(format!("objkv: scan failed: {e}"))))?;
    Ok(found
        .into_iter()
        .map(|(k, v)| {
            (String::from_utf8_lossy(&k).into_owned(), String::from_utf8_lossy(&v).into_owned())
        })
        .collect())
}

/// Whether any objkv data belongs to a database; `createdb` asks once.
pub fn database_has_rows(db: u32) -> PgResult<bool> {
    let prefix = format!("{db:08x}/").into_bytes();
    let found = with_db(|d| d.scan_prefix_at(&prefix, ::objkv::key::LATEST))?
        .map_err(|e| Box::new(PgError::error(format!("objkv: scan failed: {e}"))))?;
    Ok(!found.is_empty())
}

/// Every row of the relation at `at`, with all of this transaction's own
/// writes laid over, whichever command made them.
pub fn scan_rows(db: u32, relid: u32, at: u64) -> PgResult<Vec<(u64, Vec<u8>)>> {
    scan_rows_seen_by(db, relid, at, InvalidCommandId)
}

/// Every row of the relation as a command reading at `curcid` sees it.
pub fn scan_rows_seen_by(db: u32, relid: u32, at: u64, curcid: CommandId) -> PgResult<Vec<(u64, Vec<u8>)>> {
    let prefix = table_prefix(db, relid);
    scan_rows_between(db, relid, prefix.clone(), hi_of(&prefix), at, curcid)
}

/// Every row whose key falls in `[lo, hi)`, newest version each.
fn scan_rows_between(
    db: u32,
    relid: u32,
    lo: Vec<u8>,
    hi: Vec<u8>,
    at: u64,
    curcid: CommandId,
) -> PgResult<Vec<(u64, Vec<u8>)>> {
    // Rows older than the last TRUNCATE are still in the bucket, for a snapshot
    // taken before it. They are not in this table any more.
    let since = staged_empty_mark(&empty_marker_key(db, relid));
    // An uncommitted TRUNCATE has no sequence number, and covers everything.
    let emptied = if since > 0 {
        u64::MAX
    } else {
        emptied_at(db, relid, at)?.unwrap_or(0)
    };
    let durable = view_at(at)?.scan_window_stamped_at(&lo, &hi, at, usize::MAX)
        .map_err(|e| Box::new(PgError::error(format!("objkv: scan failed: {e}"))))?
        .0;

    let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = durable
        .into_iter()
        .filter(|(_, _, seq)| *seq >= emptied)
        .map(|(k, v, _)| (k, v))
        .collect();
    // A read into the past must not see our uncommitted writes; they belong to
    // the present. Every other read must.
    if reading_the_past() {
        return Ok(merged
            .into_iter()
            .filter_map(|(k, v)| rowid_from_key(&k).map(|id| (id, v)))
            .collect());
    }
    overlay_staged(&mut merged, &lo, &hi, since, curcid);

    Ok(merged
        .into_iter()
        .filter_map(|(k, v)| rowid_from_key(&k).map(|id| (id, v)))
        .collect())
}

/// Replaces a row's contents at the row id it already has.
///
/// The catalog's in-place update: Postgres rewrites a pg_class row inside its
/// buffer with no MVCC version, so TIDs and index entries keep pointing at it.
/// Here that is a new version under the same row key. Like Postgres's, it
/// leaves indexes alone, which is sound only because the fields updated this
/// way are never indexed ones.
pub fn update_row_in_place(db: u32, relid: u32, rowid: u64, image: Vec<u8>) -> PgResult<()> {
    refuse_writes_into_the_past()?;
    stage_in_place(row_key(db, relid, rowid), Op::Put(image));
    Ok(())
}

/// The newest value this row ever had, tombstones included: the SnapshotAny
/// re-fetch the executor does while updating a row.
pub fn fetch_row_any(db: u32, relid: u32, rowid: u64) -> PgResult<Option<Vec<u8>>> {
    let key = row_key(db, relid, rowid);
    if let Some(Op::Put(v)) = staged_op(&key) {
        return Ok(Some(v));
    }
    view()?.get_any(&key)
        .map_err(|e| Box::new(PgError::error(format!("objkv: fetch failed: {e}"))))
}

/// The row at `at` as a command reading at `curcid` sees it: this
/// transaction's own writes count from the command after the one that made
/// them, so `InvalidCommandId` sees them all.
pub fn fetch_row(db: u32, relid: u32, rowid: u64, at: u64, curcid: CommandId) -> PgResult<Option<Vec<u8>>> {
    let key = row_key(db, relid, rowid);
    let since = staged_empty_mark(&empty_marker_key(db, relid));
    if !reading_the_past() {
        match staged_seen_by(&key, curcid) {
            // Staged before a TRUNCATE this transaction ran: covered by it.
            Some((ord, _)) if ord <= since => return Ok(None),
            Some((_, Op::Put(v))) => return Ok(Some(v)),
            Some((_, Op::Delete)) => return Ok(None),
            None => {}
        }
    }
    // An uncommitted TRUNCATE has no sequence number, and covers everything.
    let emptied = if since > 0 { u64::MAX } else { emptied_at(db, relid, at)?.unwrap_or(0) };
    // Through the snapshot's view, not the Db: a cold fetch is an S3 GET,
    // and this is the path every index tuple fetch takes.
    let found = view_at(at)?
        .get_stamped_at(&key, at)
        .map_err(|e| Box::new(PgError::error(format!("objkv: fetch failed: {e}"))))?;
    Ok(found.filter(|(_, seq)| *seq >= emptied).map(|(v, _)| v))
}

/// A tombstone. Old versions stay until compaction drops them: no vacuum.
pub fn delete_row(db: u32, relid: u32, rowid: u64) -> PgResult<()> {
    refuse_writes_into_the_past()?;
    if let Some(v) = fetch_row(db, relid, rowid, ::objkv::key::LATEST, InvalidCommandId)? {
        add_stats(db, relid, -(v.len() as i64), -1);
    }
    stage(row_key(db, relid, rowid), Op::Delete)
}

/// Materialised at scan_begin: fine for a prototype, wrong for real volumes.
pub struct ObjkvScanDescData<'mcx> {
    pub rs_base: TableScanDescData<'mcx>,
    pub rows: Vec<(u64, Vec<u8>)>,
    pub next: usize,
}

impl<'mcx> ObjkvScanDescData<'mcx> {
    pub fn new(rs_base: TableScanDescData<'mcx>, rows: Vec<(u64, Vec<u8>)>) -> Self {
        ObjkvScanDescData { rs_base, rows, next: 0 }
    }
    pub fn take_next(&mut self) -> Option<(u64, Vec<u8>)> {
        let r = self.rows.get(self.next).cloned();
        if r.is_some() {
            self.next += 1;
        }
        r
    }
    pub fn rewind(&mut self) {
        self.next = 0;
    }
    /// Replaces the scan keys. next_slot filters against rs_key, so a rescan
    /// that dropped them answered from the previous call's predicate -- and a
    /// filter that is merely wrong still returns rows.
    pub fn set_keys(&mut self, key: &[::types_scan::scankey::ScanKeyData]) {
        self.rs_base.rs_key.clear();
        for k in key {
            self.rs_base.rs_key.push(k.clone());
        }
        self.rs_base.rs_nkeys = key.len() as i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: u32 = 5;

    thread_local! {
        /// What the stubbed command-id accessor answers: a test's own counter.
        static TEST_CID: std::cell::Cell<CommandId> = const { std::cell::Cell::new(0) };
    }

    /// A write is stamped through heapam's command-id accessor, which the
    /// server installs at boot. Here it answers with `TEST_CID`, which a test
    /// advances as CommandCounterIncrement would.
    fn seams() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            if !::xact_seams::get_current_command_id::is_installed() {
                ::xact_seams::get_current_command_id::set(|_used| Ok(TEST_CID.with(|c| c.get())));
            }
        });
    }

    fn cci() {
        TEST_CID.with(|c| c.set(c.get() + 1));
    }

    /// The read paths consult `pgrust.objkv_snapshot_seq`, whose slot is
    /// installed by the server's boot sequence and by nothing in a unit test.
    fn gucs() {
        seams();
        use ::guc_tables::{backing, vars, GucVarAccessors};
        vars::pgrust_objkv_snapshot_seq.install_if_absent(GucVarAccessors {
            get: backing::pgrust_objkv_snapshot_seq,
            set: backing::set_pgrust_objkv_snapshot_seq,
        });
        vars::pgrust_objkv_retain_commits.install_if_absent(GucVarAccessors {
            get: backing::pgrust_objkv_retain_commits,
            set: backing::set_pgrust_objkv_retain_commits,
        });
    }

    #[test]
    fn row_keys_sort_within_a_table_and_separate_tables() {
        assert!(row_key(DB, 7, 9) < row_key(DB, 7, 10));
        assert!(row_key(DB, 7, u64::MAX) < row_key(DB, 8, 0));
        assert!(row_key(DB, 7, 0).starts_with(&table_prefix(DB, 7)));
        assert!(!row_key(DB, 8, 0).starts_with(&table_prefix(DB, 7)));
    }

    #[test]
    fn two_databases_with_one_relid_do_not_share_rows() {
        gucs();
        assert_ne!(row_key(1, 7, 0), row_key(2, 7, 0));
        assert!(!row_key(2, 7, 0).starts_with(&table_prefix(1, 7)));

        insert_row(1, 9100, vec![1; 8]).unwrap();
        insert_row(2, 9100, vec![2; 8]).unwrap();
        let one = scan_rows(1, 9100, ::objkv::key::LATEST).unwrap();
        let two = scan_rows(2, 9100, ::objkv::key::LATEST).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(two.len(), 1);
        assert_eq!(one[0].1, vec![1; 8]);
        assert_eq!(two[0].1, vec![2; 8], "one database must not read another's rows");

        delete_row(1, 9100, one[0].0).unwrap();
        assert_eq!(scan_rows(2, 9100, ::objkv::key::LATEST).unwrap().len(), 1);
    }

    #[test]
    fn rowids_survive_the_trip_through_a_tid() {
        for id in [0u64, 1, ROWS_PER_BLOCK - 1, ROWS_PER_BLOCK, ROWS_PER_BLOCK + 1, 0x1_2345, MAX_ROWID] {
            assert_eq!(rowid_of(&tid_of(id)), id, "rowid {id:#x} round-trips");
        }
        assert_ne!(tid_of(ROWS_PER_BLOCK - 1), tid_of(ROWS_PER_BLOCK));
        assert_ne!(ItemPointerGetOffsetNumber(&tid_of(0)), 0);
    }

    #[test]
    fn keys_parse_back_to_rowids() {
        assert_eq!(rowid_from_key(&row_key(DB, 3, 0x2a)), Some(0x2a));
        assert_eq!(rowid_from_key(b"not-a-key"), None);
    }

    #[test]
    fn insert_scan_fetch_delete_round_trip() {
        gucs();
        let relid = 4242;
        let mut ids = Vec::new();
        for i in 0..5u8 {
            ids.push(insert_row(DB, relid, vec![i; 32]).unwrap());
        }
        assert_eq!(ids, vec![0, 1, 2, 3, 4], "rowids are dense and ordered");

        let rows = scan_rows(DB, relid, ::objkv::key::LATEST).unwrap();
        assert_eq!(rows.len(), 5);
        assert!(rows.windows(2).all(|w| w[0].0 < w[1].0), "scan is in rowid order");

        assert_eq!(fetch_row(DB, relid, 2, ::objkv::key::LATEST, InvalidCommandId).unwrap(), Some(vec![2u8; 32]));
        assert_eq!(fetch_row(DB, relid, 99, ::objkv::key::LATEST, InvalidCommandId).unwrap(), None);

        delete_row(DB, relid, 2).unwrap();
        assert_eq!(fetch_row(DB, relid, 2, ::objkv::key::LATEST, InvalidCommandId).unwrap(), None, "tombstone hides the row");
        let after = scan_rows(DB, relid, ::objkv::key::LATEST).unwrap();
        assert_eq!(after.len(), 4, "deleted row leaves the scan");
        assert!(!after.iter().any(|(id, _)| *id == 2));
    }

    /// `BEGIN; INSERT a; SAVEPOINT s1; SAVEPOINT s2; INSERT b; RELEASE s2;
    /// ROLLBACK TO s1; COMMIT` -- b must not commit. s1 wrote nothing, so it
    /// has no frame; the RELEASE used to merge b into the top-level frame,
    /// where the ROLLBACK could not find it.
    #[test]
    fn release_into_a_write_less_savepoint_still_rolls_back_with_it() {
        use ::types_core::xact::SubXactEvent::*;
        discard_pending();
        let (a, b) = (row_key(DB, 9300, 0), row_key(DB, 9300, 1));
        stage_in(1, a.clone(), Op::Put(vec![1]), 0); // top level
        // SAVEPOINT s1 = subid 2, no write. SAVEPOINT s2 = subid 3.
        stage_in(3, b.clone(), Op::Put(vec![2]), 0);
        objkv_subxact_callback(SUBXACT_EVENT_COMMIT_SUB, 3, 2, Datum::null()).unwrap(); // RELEASE s2
        assert_eq!(staged_op(&b), Some(Op::Put(vec![2])), "released write is still staged");
        objkv_subxact_callback(SUBXACT_EVENT_ABORT_SUB, 2, 1, Datum::null()).unwrap(); // ROLLBACK TO s1
        assert_eq!(staged_op(&b), None, "a write released into s1 goes when s1 is rolled back");
        assert_eq!(staged_op(&a), Some(Op::Put(vec![1])), "the top-level write stays");
        let committed = flatten_pending();
        assert_eq!(committed.keys().collect::<Vec<_>>(), vec![&a]);
    }

    /// RELEASE into a savepoint that did write merges into that savepoint's
    /// frame rather than stacking a second one for the same subid.
    #[test]
    fn release_merges_into_the_parents_own_frame() {
        use ::types_core::xact::SubXactEvent::*;
        discard_pending();
        let (a, b, c) = (row_key(DB, 9301, 0), row_key(DB, 9301, 1), row_key(DB, 9301, 2));
        stage_in(1, a.clone(), Op::Put(vec![1]), 0);
        stage_in(2, b.clone(), Op::Put(vec![2]), 0); // SAVEPOINT s1 writes
        stage_in(3, c.clone(), Op::Put(vec![3]), 0); // SAVEPOINT s2 writes
        stage_in(3, b.clone(), Op::Delete, 0); // ...and overwrites s1's row
        objkv_subxact_callback(SUBXACT_EVENT_COMMIT_SUB, 3, 2, Datum::null()).unwrap(); // RELEASE s2
        PENDING.with(|p| {
            let stack = p.borrow();
            assert_eq!(stack.iter().map(|f| f.subid).collect::<Vec<_>>(), vec![1, 2]);
        });
        assert_eq!(staged_op(&b), Some(Op::Delete), "the inner write wins over the parent's");
        objkv_subxact_callback(SUBXACT_EVENT_ABORT_SUB, 2, 1, Datum::null()).unwrap(); // ROLLBACK TO s1
        assert_eq!(staged_op(&b), None);
        assert_eq!(staged_op(&c), None);
        assert_eq!(staged_op(&a), Some(Op::Put(vec![1])));
        discard_pending();
    }

    /// A transaction reading at `pgrust.objkv_snapshot_seq` sees rows nobody
    /// else's commits are measured from, so it may not write; the refusal is
    /// the named read-only error, and lifts with the setting.
    #[test]
    fn writes_are_refused_while_reading_the_past() {
        use ::guc_tables::vars::pgrust_objkv_snapshot_seq as seq;
        gucs();
        let relid = 9302;
        let id = insert_row(DB, relid, vec![9; 8]).unwrap();
        seq.write(1);
        for r in [
            insert_row(DB, relid, vec![1; 8]).map(|_| ()),
            delete_row(DB, relid, id),
            update_row_in_place(DB, relid, id, vec![2; 8]),
        ] {
            let e = r.expect_err("a write while reading the past must be refused");
            assert_eq!(e.sqlstate(), ::types_error::ERRCODE_READ_ONLY_SQL_TRANSACTION);
            assert!(e.message().contains("reading a past snapshot"), "{}", e.message());
        }
        // Nothing infallible staged either: the pre-commit backstop refuses too.
        stage_raw(row_key(DB, relid, 77), vec![0]);
        let e = at_pre_commit().expect_err("pre-commit refuses staged writes under a past snapshot");
        assert_eq!(e.sqlstate(), ::types_error::ERRCODE_READ_ONLY_SQL_TRANSACTION);
        discard_pending();
        seq.write(0);
        insert_row(DB, relid, vec![3; 8]).expect("writes resume once the setting is reset");
        discard_pending();
    }

    #[test]
    fn relations_do_not_see_each_others_rows() {
        gucs();
        insert_row(DB, 7001, vec![1; 8]).unwrap();
        insert_row(DB, 7002, vec![2; 8]).unwrap();
        assert_eq!(scan_rows(DB, 7001, ::objkv::key::LATEST).unwrap().len(), 1);
        assert_eq!(scan_rows(DB, 7002, ::objkv::key::LATEST).unwrap().len(), 1);
        assert_ne!(
            scan_rows(DB, 7001, ::objkv::key::LATEST).unwrap()[0].1,
            scan_rows(DB, 7002, ::objkv::key::LATEST).unwrap()[0].1
        );
        assert!(scan_rows(DB, 7003, ::objkv::key::LATEST).unwrap().is_empty());
    }

    /// `UPDATE t SET k = k + 1 WHERE k > 5`, read a window at a time: the rows
    /// the statement has already moved must not turn up in a later window.
    /// Heap's rule, applied to the staged set: a write is seen from the
    /// command after the one that made it, and a delete hides nothing from
    /// the command that made it.
    #[test]
    fn a_command_does_not_see_its_own_writes() {
        gucs();
        discard_pending();
        let relid = 9400;
        // Command 0 inserts; a scan of command 0 does not see the row.
        let id = insert_row(DB, relid, vec![1; 8]).unwrap();
        assert!(scan_rows_seen_by(DB, relid, ::objkv::key::LATEST, 0).unwrap().is_empty());
        assert_eq!(fetch_row(DB, relid, id, ::objkv::key::LATEST, 0).unwrap(), None);
        // Everything of ours, whichever command wrote it: what the row-id
        // seeding scan and the uniqueness check ask.
        assert_eq!(scan_rows(DB, relid, ::objkv::key::LATEST).unwrap().len(), 1);
        assert_eq!(staged_op(&row_key(DB, relid, id)), Some(Op::Put(vec![1; 8])));
        cci();
        // Command 1 sees it ...
        assert_eq!(fetch_row(DB, relid, id, ::objkv::key::LATEST, 1).unwrap(), Some(vec![1; 8]));
        assert_eq!(scan_rows_seen_by(DB, relid, ::objkv::key::LATEST, 1).unwrap().len(), 1);
        // ... and deletes it; the row stays visible to command 1's own scan,
        // as a heap tuple whose cmax is the current command does.
        delete_row(DB, relid, id).unwrap();
        assert_eq!(fetch_row(DB, relid, id, ::objkv::key::LATEST, 1).unwrap(), Some(vec![1; 8]));
        assert_eq!(scan_rows_seen_by(DB, relid, ::objkv::key::LATEST, 1).unwrap().len(), 1);
        assert_eq!(staged_op(&row_key(DB, relid, id)), Some(Op::Delete));
        cci();
        assert_eq!(fetch_row(DB, relid, id, ::objkv::key::LATEST, 2).unwrap(), None);
        assert!(scan_rows_seen_by(DB, relid, ::objkv::key::LATEST, 2).unwrap().is_empty());
        // What commits is the newest version.
        assert_eq!(flatten_pending().get(&row_key(DB, relid, id)), Some(&Op::Delete));
        discard_pending();
    }

    /// The in-place catalog update is seen at once, as heap's is: by every
    /// command when the row is in the store, and from the command after the
    /// one that inserted it when this transaction did.
    #[test]
    fn an_in_place_update_is_seen_as_the_version_it_rewrites() {
        gucs();
        discard_pending();
        let relid = 9401;
        // A row nobody staged: the rewrite is seen even by command 0.
        update_row_in_place(DB, relid, 7, vec![7; 8]).unwrap();
        assert_eq!(fetch_row(DB, relid, 7, ::objkv::key::LATEST, 0).unwrap(), Some(vec![7; 8]));
        // Inserted by command 0, rewritten by command 2: the rewrite reads
        // from command 1 on, and command 0 still has no row.
        let id = insert_row(DB, relid, vec![1; 8]).unwrap();
        cci();
        cci();
        update_row_in_place(DB, relid, id, vec![2; 8]).unwrap();
        assert_eq!(fetch_row(DB, relid, id, ::objkv::key::LATEST, 0).unwrap(), None);
        assert_eq!(fetch_row(DB, relid, id, ::objkv::key::LATEST, 1).unwrap(), Some(vec![2; 8]));
        assert_eq!(fetch_row(DB, relid, id, ::objkv::key::LATEST, 2).unwrap(), Some(vec![2; 8]));
        discard_pending();
    }

    /// A savepoint deletes a row the transaction inserted earlier: the
    /// deleting command still sees the row, the next does not, a rollback of
    /// the savepoint brings it back for both, and a release keeps the
    /// versions apart.
    #[test]
    fn a_savepoints_write_hides_the_outer_version_from_later_commands_only() {
        use ::types_core::xact::SubXactEvent::*;
        discard_pending();
        let a = row_key(DB, 9402, 0);
        let seen = |curcid| staged_seen_by(&a, curcid).map(|(_, op)| op);
        stage_in(1, a.clone(), Op::Put(vec![1]), 3); // command 3, top level
        stage_in(2, a.clone(), Op::Delete, 5); // SAVEPOINT s1 = subid 2, command 5
        assert_eq!(seen(3), None);
        assert_eq!(seen(5), Some(Op::Put(vec![1])));
        assert_eq!(seen(6), Some(Op::Delete));
        assert_eq!(
            staged_range(&a, &hi_of(&a), 5).get(&a).map(|(_, op)| op.clone()),
            Some(Op::Put(vec![1])),
            "a window merge reads the outer version too"
        );
        objkv_subxact_callback(SUBXACT_EVENT_ABORT_SUB, 2, 1, Datum::null()).unwrap(); // ROLLBACK TO s1
        assert_eq!(seen(6), Some(Op::Put(vec![1])));
        stage_in(2, a.clone(), Op::Delete, 5);
        objkv_subxact_callback(SUBXACT_EVENT_COMMIT_SUB, 2, 1, Datum::null()).unwrap(); // RELEASE s1
        assert_eq!(seen(5), Some(Op::Put(vec![1])), "the release keeps the version it replaced");
        assert_eq!(seen(6), Some(Op::Delete));
        assert_eq!(flatten_pending().get(&a), Some(&Op::Delete));
    }
}

pub fn relid(rel: &Relation<'_>) -> u32 {
    rel.rd_id
}

pub fn begin_scan<'mcx>(
    relation: &Relation<'mcx>,
    snapshot: ::tableam_vocab::Snapshot<'mcx>,
    nkeys: i32,
    key: ::mcx::PgVec<'mcx, ::types_scan::scankey::ScanKeyData>,
    flags: u32,
) -> PgResult<TableScanDesc<'mcx>> {
    let rows = scan_rows_seen_by(
        scope(relation),
        relid(relation),
        snapshot_seq(snapshot.as_deref())?,
        snapshot_cid(snapshot.as_deref()),
    )?;
    Ok(desc(relation, snapshot, nkeys, key, flags, rows))
}

/// A bitmap scan reads nothing up front: the row ids arrive from the index
/// side a block at a time, and each block is fetched when it comes.
pub fn begin_scan_bitmap<'mcx>(
    mcx: Mcx<'mcx>,
    relation: &Relation<'mcx>,
    snapshot: ::tableam_vocab::Snapshot<'mcx>,
    flags: u32,
) -> PgResult<TableScanDesc<'mcx>> {
    Ok(desc(relation, snapshot, 0, ::mcx::PgVec::new_in(mcx), flags, Vec::new()))
}

fn desc<'mcx>(
    relation: &Relation<'mcx>,
    snapshot: ::tableam_vocab::Snapshot<'mcx>,
    nkeys: i32,
    key: ::mcx::PgVec<'mcx, ::types_scan::scankey::ScanKeyData>,
    flags: u32,
    rows: Vec<(u64, Vec<u8>)>,
) -> TableScanDesc<'mcx> {
    TableScanDesc::Objkv(std::boxed::Box::new(ObjkvScanDescData::new(
        TableScanDescData {
            rs_rd: relation.alias(),
            rs_snapshot: snapshot,
            rs_nkeys: nkeys,
            rs_key: key,
            rs_mintid: ItemPointerData::invalid(),
            rs_maxtid: ItemPointerData::invalid(),
            rs_flags: flags,
            rs_parallel: None,
            rs_am: ::tableam_vocab::TableAm::Objkv,
        },
        rows,
    )))
}

/// Stages the next bitmap block's rows; 0 means the bitmap is finished.
///
/// A block here is a range of row ids rather than a page on a disk, so a lossy
/// entry -- one the bitmap shrank to "some row on this block" under memory
/// pressure -- is a range read, and the caller rechecks.
pub fn scan_bitmap_next_pagebatch(
    scan: &mut ObjkvScanDescData<'_>,
    tbm: Option<&::tidbitmap::TIDBitmap<'_>>,
    iterator: &mut ::tidbitmap::TbmIterator,
    recheck: &mut bool,
    lossy_pages: &mut u64,
    exact_pages: &mut u64,
) -> PgResult<u32> {
    let db = scope(&scan.rs_base.rs_rd);
    let rel = relid(&scan.rs_base.rs_rd);
    let at = snapshot_seq(scan.rs_base.rs_snapshot.as_deref())?;
    let curcid = snapshot_cid(scan.rs_base.rs_snapshot.as_deref());
    loop {
        let Some(page) = iterator.next(tbm) else { return Ok(0) };
        let base = page.blockno as u64 * ROWS_PER_BLOCK;
        let rows = if page.lossy {
            *lossy_pages += 1;
            *recheck = true;
            scan_rows_between(
                db,
                rel,
                row_key(db, rel, base),
                row_key(db, rel, base + ROWS_PER_BLOCK),
                at,
                curcid,
            )?
        } else {
            *exact_pages += 1;
            *recheck = page.recheck;
            let mut offsets = [0u16; ROWS_PER_BLOCK as usize];
            let n = page.extract_page_tuples(&mut offsets);
            let mut rows = Vec::with_capacity(n);
            for &off in &offsets[..n.min(offsets.len())] {
                let rowid = base + off as u64 - 1;
                if let Some(image) = fetch_row(db, rel, rowid, at, curcid)? {
                    rows.push((rowid, image));
                }
            }
            rows
        };
        if !rows.is_empty() {
            let n = rows.len() as u32;
            scan.rows = rows;
            scan.rewind();
            return Ok(n);
        }
    }
}

pub fn scan_bitmap_batch_store<'mcx>(
    mcx: Mcx<'mcx>,
    scan: &mut ObjkvScanDescData<'mcx>,
    i: u32,
    slot: &mut SlotData<'mcx>,
) {
    let (rowid, image) = scan.rows[i as usize].clone();
    let _ = store_image(mcx, slot, &image, tid_of(rowid));
}

pub fn scan_bitmap_next_tuple<'mcx>(
    mcx: Mcx<'mcx>,
    scan: &mut ObjkvScanDescData<'mcx>,
    tbm: Option<&::tidbitmap::TIDBitmap<'_>>,
    iterator: &mut ::tidbitmap::TbmIterator,
    slot: &mut SlotData<'mcx>,
    recheck: &mut bool,
    lossy_pages: &mut u64,
    exact_pages: &mut u64,
) -> PgResult<bool> {
    while scan.next >= scan.rows.len() {
        if scan_bitmap_next_pagebatch(scan, tbm, iterator, recheck, lossy_pages, exact_pages)? == 0 {
            ::exectuples::exec_clear_tuple(slot, mcx);
            return Ok(false);
        }
    }
    let (rowid, image) = scan.rows[scan.next].clone();
    scan.next += 1;
    store_image(mcx, slot, &image, tid_of(rowid))?;
    Ok(true)
}

/// No visibility recheck: the layer merge dropped tombstones already.
pub fn next_slot<'mcx>(
    mcx: Mcx<'mcx>,
    scan: &mut ObjkvScanDescData<'mcx>,
    slot: &mut SlotData<'mcx>,
) -> PgResult<bool> {
    loop {
        let Some((rowid, image)) = scan.take_next() else {
            ::exectuples::exec_clear_tuple(slot, mcx);
            return Ok(false);
        };
        store_image(mcx, slot, &image, tid_of(rowid))?;

        // Scan keys are the AM's job: a catalog scan through genam has no filter
        // node above it and believes every row it gets.
        if scan.rs_base.rs_nkeys > 0 {
            let mut tuple = ::heaptuple::HeapTuple::alloc_zeroed(mcx, image.len())?;
            tuple.image_mut().copy_from_slice(&image);
            tuple.as_tuple_mut().t_self = tid_of(rowid);
            let desc = scan.rs_base.rs_rd.rd_att.clone();
            if !::heapam::heap_key_test(tuple.as_tuple(), &desc, &mut scan.rs_base.rs_key)? {
                continue;
            }
        }
        return Ok(true);
    }
}

pub fn tuple_insert<'mcx>(
    mcx: Mcx<'mcx>,
    rel: &Relation<'mcx>,
    slot: &mut SlotData<'mcx>,
) -> PgResult<()> {
    ::exectuples::slot_getallattrs(slot);
    let image = {
        let base = slot.base();
        let desc = base
            .tts_tupleDescriptor
            .as_ref()
            .expect("objkv insert slot without a descriptor");
        encode_row(mcx, desc, &base.tts_values, &base.tts_isnull)?
    };
    let rowid = insert_row(scope(rel), relid(rel), image)?;
    slot.base_mut().tts_tid = tid_of(rowid);
    Ok(())
}

/// Inserts a catalog row that is already formed, and stamps its TID. The
/// catalog path forms its tuple before it knows where it will live, so it
/// arrives as an image rather than a slot; nothing else differs.
pub fn insert_tuple_image(rel: &Relation<'_>, tup: &mut HeapTupleData<'_>) -> PgResult<()> {
    let image = catalog_image(rel, tup)?;
    let rowid = insert_row(scope(rel), relid(rel), image)?;
    tup.t_self = tid_of(rowid);
    // heap_insert stamps this too, and the index path asserts on it.
    tup.t_tableOid = rel.rd_id;
    Ok(())
}

/// Replaces a catalog row's contents at the row id it has. Not the ordinary
/// UPDATE, which writes at a fresh one: entries name the row id, and the
/// catalog's own indexes would be left pointing at nothing.
pub fn update_tuple_image(
    rel: &Relation<'_>,
    otid: &ItemPointerData,
    tup: &mut HeapTupleData<'_>,
) -> PgResult<()> {
    // Same row id, new contents: the entries for the old contents would
    // otherwise stay, pointing at a row that no longer carries that value.
    let cx = ::mcx::MemoryContext::new("objkv retire entries");
    crate::objkv_index::retire_entries(cx.mcx(), rel, rowid_of(otid))?;
    let image = catalog_image(rel, tup)?;
    let rowid = rowid_of(otid);
    update_row_in_place(scope(rel), relid(rel), rowid, image)?;
    tup.t_self = *otid;
    tup.t_tableOid = rel.rd_id;
    Ok(())
}

pub fn tuple_delete(rel: &Relation<'_>, tid: &ItemPointerData) -> PgResult<()> {
    // Before the row goes: the entry keys are read off the row as it stands.
    // Its own context because eighty places delete a catalog row and none hand
    // one down; nothing allocated here outlives the call.
    let cx = ::mcx::MemoryContext::new("objkv retire entries");
    crate::objkv_index::retire_entries(cx.mcx(), rel, rowid_of(tid))?;
    delete_row(scope(rel), relid(rel), rowid_of(tid))
}

/// Delete plus insert, as MVCC does anyway -- except the old version becomes
/// an old object rather than a dead tuple somebody has to vacuum.
pub fn tuple_update<'mcx>(
    mcx: Mcx<'mcx>,
    rel: &Relation<'mcx>,
    old_tid: &ItemPointerData,
    slot: &mut SlotData<'mcx>,
) -> PgResult<()> {
    crate::objkv_index::retire_entries(mcx, rel, rowid_of(old_tid))?;
    delete_row(scope(rel), relid(rel), rowid_of(old_tid))?;
    tuple_insert(mcx, rel, slot)
}

pub fn satisfies_snapshot(
    rel: &Relation<'_>,
    tid: &ItemPointerData,
    snapshot: Option<&SnapshotData<'_>>,
) -> PgResult<bool> {
    Ok(fetch_row(scope(rel), relid(rel), rowid_of(tid), snapshot_seq(snapshot)?, snapshot_cid(snapshot))?
        .is_some())
}

/// Whether the row is there now, this transaction's every write counted.
pub fn row_exists(rel: &Relation<'_>, tid: &ItemPointerData) -> PgResult<bool> {
    Ok(fetch_row(scope(rel), relid(rel), rowid_of(tid), ::objkv::key::LATEST, InvalidCommandId)?.is_some())
}

pub fn index_fetch<'mcx>(
    mcx: Mcx<'mcx>,
    rel: &Relation<'mcx>,
    tid: &ItemPointerData,
    slot: &mut SlotData<'mcx>,
    snapshot: Option<&SnapshotData<'_>>,
) -> PgResult<bool> {
    let any = snapshot.is_some_and(|s| {
        matches!(s.snapshot_type, ::types_snapshot::SnapshotType::SNAPSHOT_ANY)
    });
    let found = if any {
        fetch_row_any(scope(rel), relid(rel), rowid_of(tid))?
    } else {
        fetch_row(scope(rel), relid(rel), rowid_of(tid), snapshot_seq(snapshot)?, snapshot_cid(snapshot))?
    };
    match found {
        Some(image) => {
            store_image(mcx, slot, &image, *tid)?;
            Ok(true)
        }
        None => Ok(false),
    }
}
