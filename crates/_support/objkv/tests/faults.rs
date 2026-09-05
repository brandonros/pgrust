//! The engine under a misbehaving store.
//!
//! A `Db` is driven through its production API -- the calls the table AM's
//! writer, compactor and abort paths make, retries included -- over a
//! [`FaultStore`] wrapping a `MemStore`. Each test loops over seeds; a
//! failure names the seed and prints the tail of the store's operation log,
//! so it replays.
//!
//! The invariants are the ones a client can hold the engine to:
//!
//! * a commit whose client was told it is durable is readable after a
//!   fresh open of the same bucket;
//! * a commit whose client was told it failed or aborted is never readable;
//! * an open never panics and never serves part of a torn object.
//!
//! A test that fails is a finding, not a test to weaken: it stays here,
//! ignored, with the seed in its reason.

use std::any::Any;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use objkv::commit::Op;
use objkv::db::{self, Db, Discard, Outcome};
use objkv::faults::{Fault, FaultStore, OpKind, Rule, XorShift};
use objkv::key::LATEST;
use objkv::s3::PutOutcome;
use objkv::store::{MemStore, Store};

const SEEDS: u64 = 200;

// ---- the bucket and the AM's side of the API --------------------------------

struct Bucket {
    mem: Arc<MemStore>,
    faults: Arc<FaultStore>,
    store: Arc<dyn Store>,
    /// The host's local directory for the pending-discard journal, as the
    /// AM's open passes one under the data directory. Every restart in a
    /// test is a restart on the same host.
    journal: PathBuf,
}

static BUCKETS: AtomicU64 = AtomicU64::new(0);

fn bucket(seed: u64) -> Bucket {
    let mem = Arc::new(MemStore::new());
    let faults = Arc::new(FaultStore::new(Arc::clone(&mem) as Arc<dyn Store>, seed));
    let store = Arc::clone(&faults) as Arc<dyn Store>;
    let n = BUCKETS.fetch_add(1, Ordering::Relaxed);
    let journal = std::env::temp_dir().join(format!("objkv-faults-{}-{seed}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&journal);
    Bucket { mem, faults, store, journal }
}

impl Drop for Bucket {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.journal);
    }
}

impl Bucket {
    /// A restart: a fresh writer on the bucket as it stands, on the same
    /// host.
    fn open(&self) -> std::io::Result<Db> {
        Db::open_with_journal(Arc::clone(&self.store), &self.journal)
    }

    fn failure(&self, seed: u64, what: &str) -> String {
        format!(
            "seed {seed}: {what}\n--- faults injected: {} ---\n{}--- last operations ---\n{}--- torn keys: {:?}",
            self.faults.faults_injected(),
            self.faults.faults().iter().map(|e| format!("{e}\n")).collect::<String>(),
            self.faults.tail(40),
            self.faults.torn_keys()
        )
    }
}

fn one(k: &[u8], v: &[u8]) -> BTreeMap<Vec<u8>, Op> {
    let mut w = BTreeMap::new();
    w.insert(k.to_vec(), Op::Put(v.to_vec()));
    w
}

fn writes(rows: &[(Vec<u8>, Vec<u8>)]) -> BTreeMap<Vec<u8>, Op> {
    rows.iter().map(|(k, v)| (k.clone(), Op::Put(v.clone()))).collect()
}

/// One flight, the way the AM's writer thread flies it: three attempts at
/// the PUT, then `flight_failed`. An existing key is `flight_lost`.
fn fly(d: &mut Db, s: &Arc<dyn Store>) -> bool {
    let Some(f) = d.take_flight() else { return false };
    for attempt in 1..=3 {
        match s.put_if_absent(&f.key, &f.bytes) {
            Ok(PutOutcome::Written) => {
                d.flight_written(f.first);
                break;
            }
            Ok(PutOutcome::AlreadyExists) => {
                let _ = d.flight_lost(&f);
                break;
            }
            Err(_) if attempt < 3 => continue,
            Err(e) => {
                d.flight_failed(f.first, &e.to_string());
                break;
            }
        }
    }
    true
}

/// One whole synchronous transaction with no faults expected: stage, fly,
/// confirm. Panics on anything but `Durable`.
fn commit(d: &mut Db, s: &Arc<dyn Store>, w: BTreeMap<Vec<u8>, Op>, xid: u32) -> u64 {
    let (t, seq) = d.stage_commit(w, xid, LATEST, true).unwrap().unwrap().expect("non-empty");
    fly(d, s);
    match d.take_outcome(t) {
        Some(Outcome::Durable(x)) => assert_eq!(x, seq),
        other => panic!("expected Durable, got {other:?}"),
    }
    d.mark_confirmed(seq);
    seq
}

/// One fold, the way the compactor thread does it, with a store that may
/// fail any step. `Ok(true)` when a run was written and swapped in.
///
/// `collected` is raised to `horizon` as soon as the run's PUT is attempted:
/// from then on the run -- with history at or below the horizon dropped --
/// may be in the bucket whatever the PUT said, and a restart would use it.
fn fold(d: &mut Db, s: &Arc<dyn Store>, horizon: u64, collected: &mut u64) -> std::io::Result<bool> {
    let Some(plan) = d.fold_plan() else { return Ok(false) };
    let folded = db::build_fold(&plan, horizon, &BTreeMap::new())?;
    *collected = (*collected).max(horizon);
    db::put_fold(s, &folded)?;
    let sweep = d.apply_fold(plan, &folded, horizon)?;
    let result = db::execute_sweep(s, sweep);
    d.sweep_done(result);
    Ok(true)
}

fn panic_message(p: Box<dyn Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = p.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    "non-string panic payload".to_string()
}

/// The engine's designed fatal paths announce themselves. Anything else is
/// a crash.
fn is_designed_fatal(msg: &str) -> bool {
    msg.starts_with("objkv PANIC:")
}

fn row(i: u64) -> Vec<u8> {
    format!("row/{i:02}").into_bytes()
}

// ---- 1. a PUT whose response was lost ---------------------------------------

/// The commit object lands, the 200 never arrives. Whatever the engine
/// decides, what it tells the client and what the bucket holds afterwards
/// must agree.
#[test]
fn a_lost_response_on_the_commit_put_never_lies_to_the_client() {
    let mut told_durable = 0;
    let mut fenced = 0;
    for seed in 0..SEEDS {
        let b = bucket(seed);
        let mut d = b.open().unwrap();
        commit(&mut d, &b.store, one(b"base", b"1"), 1);

        // Three shapes of the same accident. The writer retries a failed
        // PUT twice, so one lost response is seen again as `AlreadyExists`;
        // three lost responses end in `flight_failed`, which asks the
        // bucket; and a bucket that cannot be asked leaves the outcome
        // unknown.
        let shape = seed % 3;
        match shape {
            0 => b.faults.add_rule(Rule::nth(OpKind::Put, "commit/", 1, Fault::ErrAfterLanded)),
            1 => b.faults.add_rule(Rule::first(OpKind::Put, "commit/", 3, Fault::ErrAfterLanded)),
            _ => {
                b.faults.add_rule(Rule::first(OpKind::Put, "commit/", 3, Fault::ErrAfterLanded));
                b.faults.add_rule(Rule::nth(OpKind::Get, "commit/", 1, Fault::GetErr));
            }
        }
        // One or two transactions in the flight.
        let members = 1 + (seed / 3) % 2;
        let mut staged = Vec::new();
        for i in 0..members {
            let k = format!("k{i}").into_bytes();
            let v = format!("v{seed}").into_bytes();
            let (t, seq) = d.stage_commit(one(&k, &v), 10 + i as u32, LATEST, true).unwrap().unwrap().unwrap();
            staged.push((t, seq, k, v));
        }
        assert!(fly(&mut d, &b.store), "{}", b.failure(seed, "no flight"));
        let mut outcomes = Vec::new();
        for (t, seq, k, v) in staged {
            let o = d.take_outcome(t);
            if let Some(Outcome::Durable(x)) = &o {
                assert_eq!(*x, seq);
                d.mark_confirmed(seq);
            }
            outcomes.push((o, k, v));
        }
        let was_fenced = d.is_fenced();
        drop(d);

        b.faults.set_enabled(false);
        let r = b.open().unwrap_or_else(|e| panic!("{}", b.failure(seed, &format!("reopen failed: {e}"))));
        for (o, k, v) in outcomes {
            let seen = r.get(&k).unwrap();
            match o {
                Some(Outcome::Durable(_)) => {
                    told_durable += 1;
                    assert!(!was_fenced, "{}", b.failure(seed, "told Durable by a fenced process"));
                    assert_eq!(seen, Some(v), "{}", b.failure(seed, "client told OK but the row is gone after reopen"));
                }
                Some(Outcome::Failed(_)) => {
                    assert_eq!(seen, None, "{}", b.failure(seed, "client told error but the row is visible after reopen"));
                }
                Some(Outcome::Fenced(why)) => {
                    fenced += 1;
                    assert_eq!(shape, 2, "{}", b.failure(seed, &format!("fenced with the bucket readable: {why}")));
                    assert!(why.contains("unknown"), "{}", b.failure(seed, &format!("a fence over a lost response must say the outcome is unknown: {why}")));
                }
                other => panic!("{}", b.failure(seed, &format!("unexpected outcome {other:?}"))),
            }
        }
        assert_eq!(r.get(b"base").unwrap(), Some(b"1".to_vec()));
    }
    assert!(told_durable > 0 && fenced > 0, "the loop did not exercise both outcomes ({told_durable}, {fenced})");
}

// ---- 2. torn objects in the bucket at open ---------------------------------

/// A bucket with a run and some commits on top of it, and what its rows
/// should read as.
fn populated(b: &Bucket, seed: u64) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut d = b.open().unwrap();
    let mut expect = BTreeMap::new();
    let rows = 40;
    for i in 0..rows {
        let v = format!("a{seed}-{i}").into_bytes();
        commit(&mut d, &b.store, one(&row(i), &v), i as u32);
        expect.insert(row(i), v);
    }
    assert!(fold(&mut d, &b.store, 0, &mut 0).unwrap());
    for i in 0..rows / 4 {
        let v = format!("b{seed}-{i}").into_bytes();
        commit(&mut d, &b.store, one(&row(i * 4), &v), 100 + i as u32);
        expect.insert(row(i * 4), v);
    }
    expect
}

/// Tears one live object of the given prefix in place, underneath the
/// faults. Returns its key.
fn tear_one(b: &Bucket, rng: &mut XorShift, prefix: &str) -> String {
    let mut keys: Vec<String> = b.mem.list(prefix).unwrap().into_iter().map(|i| i.key).collect();
    keys.sort();
    let key = keys[rng.below(keys.len() as u64) as usize].clone();
    let body = b.mem.get(&key).unwrap().unwrap();
    let torn = FaultStore::tear(rng, &body);
    b.mem.delete(&key).unwrap();
    b.mem.put_if_absent(&key, &torn).unwrap();
    key
}

/// Opens over a bucket holding one torn object and reads every row: the
/// open may refuse, a read may fail, but nothing may come back wrong.
/// `Ok` says what happened, for the caller to count; `Err` is a wrong
/// answer.
fn open_over_torn(b: &Bucket, seed: u64, key: &str, expect: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<&'static str, String> {
    let opened = catch_unwind(AssertUnwindSafe(|| b.open()));
    let d = match opened {
        Err(p) => return Err(b.failure(seed, &format!("open panicked over torn `{key}`: {}", panic_message(p)))),
        Ok(Err(_)) => return Ok("open refused"),
        Ok(Ok(d)) => d,
    };
    let mut read_errs = 0;
    for (k, v) in expect {
        match d.get(k) {
            Ok(got) if got.as_ref() == Some(v) => {}
            Ok(got) => {
                return Err(b.failure(
                    seed,
                    &format!(
                        "row {:?} reads {:?}, not {:?}, over torn `{key}`",
                        String::from_utf8_lossy(k),
                        got.as_deref().map(String::from_utf8_lossy),
                        String::from_utf8_lossy(v)
                    ),
                ))
            }
            Err(_) => read_errs += 1,
        }
    }
    match d.scan_prefix(b"row/") {
        Ok(rows) => {
            let got: BTreeMap<Vec<u8>, Vec<u8>> = rows.into_iter().collect();
            if &got != expect {
                return Err(b.failure(seed, &format!("scan reads {} rows, not {}, over torn `{key}`", got.len(), expect.len())));
            }
        }
        Err(_) => read_errs += 1,
    }
    Ok(if read_errs > 0 { "open ok, reads refused" } else { "open ok, reads right" })
}

/// Tears one live object under `prefix` per seed and opens over it.
/// Panics at the end with the distribution of outcomes if any seed read a
/// wrong answer.
fn torn_objects_under(prefix: &str) {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut wrong: Vec<(u64, String)> = Vec::new();
    for seed in 0..SEEDS {
        let b = bucket(seed);
        let expect = populated(&b, seed);
        let mut rng = XorShift::new(seed);
        let key = tear_one(&b, &mut rng, prefix);
        match open_over_torn(&b, seed, &key, &expect) {
            Ok(what) => *counts.entry(what).or_insert(0) += 1,
            Err(why) => {
                *counts.entry("WRONG ANSWER").or_insert(0) += 1;
                wrong.push((seed, why));
            }
        }
    }
    eprintln!("torn `{prefix}` objects over {SEEDS} seeds: {counts:?}");
    if let Some((seed, why)) = wrong.first() {
        let seeds: Vec<u64> = wrong.iter().map(|(s, _)| *s).collect();
        panic!("{} seed(s) read a wrong answer over a torn `{prefix}` object: {seeds:?}\n{counts:?}\nfirst, seed {seed}:\n{why}", wrong.len());
    }
}

#[test]
fn a_torn_commit_object_is_refused_not_applied() {
    torn_objects_under("commit/");
}

#[test]
fn a_torn_run_object_is_refused_not_applied() {
    torn_objects_under("run/");
}

// ---- 3. the discard marker cannot be written -------------------------------

/// Stages, lands and then aborts one transaction whose marker PUT fails
/// the given way. Returns the marker's key and the aborted row's value.
fn abort_with_failing_marker(b: &Bucket, seed: u64, how: Fault) -> (Db, String, Vec<u8>) {
    let mut d = b.open().unwrap();
    commit(&mut d, &b.store, one(b"base", b"1"), 1);
    let v = format!("aborted{seed}").into_bytes();
    let (t, seq) = d.stage_commit(one(b"k", &v), 42, LATEST, true).unwrap().unwrap().unwrap();
    fly(&mut d, &b.store);
    assert!(matches!(d.take_outcome(t), Some(Outcome::Durable(_))));
    // Postgres aborts; the object is in the bucket.
    let m = d.begin_discard(seq, Discard::Aborted).expect("the object landed, so a marker is owed");
    b.faults.add_rule(Rule::first(OpKind::Put, "resolve/", 3, how));
    let err = m.write(&b.store).expect_err("the marker PUT fails");
    let r = catch_unwind(AssertUnwindSafe(|| d.discard_failed(&m, &err)));
    let msg = panic_message(r.expect_err("discard_failed does not return"));
    assert!(is_designed_fatal(&msg), "{}", b.failure(seed, &format!("not the designed fatal: {msg}")));
    assert!(d.is_fenced(), "{}", b.failure(seed, "the process went on as if the abort held"));
    assert!(d.stage_commit(one(b"q", b"1"), 3, LATEST, true).is_err());
    (d, db::discard_key(seq), v)
}

#[test]
fn a_failed_discard_marker_write_is_fatal_and_the_by_hand_marker_holds() {
    for seed in 0..SEEDS {
        let b = bucket(seed);
        let how = if seed % 2 == 0 { Fault::ErrBeforeLanded } else { Fault::ErrAfterLanded };
        let (d, marker_key, v) = abort_with_failing_marker(&b, seed, how);
        drop(d);
        b.faults.set_enabled(false);

        // What the panic told the operator to do.
        let landed = b.mem.get(&marker_key).unwrap().is_some();
        assert_eq!(landed, how == Fault::ErrAfterLanded, "{}", b.failure(seed, "marker presence"));
        if !landed {
            let body = format!("discard:aborted\nxid:42\ncrc:{:08x}\n", 0);
            // The crc is checked against the object; use the exact body the
            // panic message quotes instead of guessing it.
            let _ = body;
        }
        // Reopen after the operator's fix. With the marker landed the fix is
        // a no-op; without it, the operator must create it.
        if !landed {
            let want = marker_body_for(&b, &marker_key);
            b.mem.put_if_absent(&marker_key, &want).unwrap();
        }
        let r = b.open().unwrap();
        assert_eq!(r.get(b"k").unwrap(), None, "{}", b.failure(seed, "the aborted transaction is visible despite the marker"));
        assert_eq!(r.get(b"base").unwrap(), Some(b"1".to_vec()));
        let _ = v;
    }
}

/// The body the by-hand marker needs: the commit object's fingerprint, read
/// from the bucket the way an operator following the panic message would
/// (the message quotes the body verbatim; this recomputes it).
fn marker_body_for(b: &Bucket, marker_key: &str) -> Vec<u8> {
    let seq = u64::from_str_radix(marker_key.rsplit('/').next().unwrap(), 16).unwrap();
    let obj = b.mem.get(&objkv::commit::key_for(seq)).unwrap().expect("the object landed");
    let members = objkv::commit::decode_members(&obj).unwrap();
    let (c, crc) = members.iter().find(|(c, _)| c.seq == seq).unwrap();
    format!("discard:aborted\nxid:{}\ncrc:{crc:08x}\n", c.xid).into_bytes()
}

/// After the fatal, a plain restart -- no operator action -- must not apply
/// a transaction whose client was told it aborted. Nothing in the bucket
/// records the abort, so the next open applies the object; the panic
/// message asks a human to intervene before the restart that a postmaster
/// performs on its own.
#[test]
fn a_plain_restart_after_a_failed_discard_marker_does_not_apply_the_aborted_transaction() {
    for seed in 0..SEEDS {
        let b = bucket(seed);
        let (d, _marker_key, _v) = abort_with_failing_marker(&b, seed, Fault::ErrBeforeLanded);
        drop(d);
        b.faults.set_enabled(false);
        let r = b.open().unwrap();
        assert_eq!(
            r.get(b"k").unwrap(),
            None,
            "{}",
            b.failure(seed, "client told abort (then the server died) but the row is visible after a plain restart")
        );
    }
}

// ---- 4. random faults on every operation -----------------------------------

/// What the clients were told, kept apart from what the engine holds.
#[derive(Default)]
struct Model {
    /// Per row: the value of the newest commit told durable, and its number.
    known: BTreeMap<Vec<u8>, (Vec<u8>, u64)>,
    /// Per row: values of commits above the known one whose outcome the
    /// client never learned (fenced, crashed mid-flight, died in a designed
    /// fatal). Any of them may or may not be there.
    unknown: BTreeMap<Vec<u8>, Vec<(Vec<u8>, u64)>>,
    /// Values the client was told will never be there: (row, value, seq, why).
    dead: Vec<(Vec<u8>, Vec<u8>, u64, &'static str)>,
    /// Every commit told durable, for the read-at-its-number check.
    durable: Vec<(u64, Vec<(Vec<u8>, Vec<u8>)>)>,
    /// The highest horizon any fold was built with: history at or below
    /// it is gone by design, so no read at those numbers is checked.
    collected: u64,
    stats: Stats,
}

#[derive(Default, Debug)]
struct Stats {
    commits_ok: u64,
    async_ok: u64,
    failed: u64,
    aborted: u64,
    aborted_unwritten: u64,
    fenced: u64,
    async_lost: u64,
    no_outcome: u64,
    folds: u64,
    fold_errs: u64,
    reads_ok: u64,
    read_errs: u64,
    reopens: u64,
    open_errs: u64,
    designed_fatals: u64,
    unopenable_torn: u64,
    faults: u64,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.commits_ok += o.commits_ok;
        self.async_ok += o.async_ok;
        self.failed += o.failed;
        self.aborted += o.aborted;
        self.aborted_unwritten += o.aborted_unwritten;
        self.fenced += o.fenced;
        self.async_lost += o.async_lost;
        self.no_outcome += o.no_outcome;
        self.folds += o.folds;
        self.fold_errs += o.fold_errs;
        self.reads_ok += o.reads_ok;
        self.read_errs += o.read_errs;
        self.reopens += o.reopens;
        self.open_errs += o.open_errs;
        self.designed_fatals += o.designed_fatals;
        self.unopenable_torn += o.unopenable_torn;
        self.faults += o.faults;
    }
}

impl Model {
    fn begin(&mut self, seq: u64, rows: &[(Vec<u8>, Vec<u8>)]) {
        for (k, v) in rows {
            self.unknown.entry(k.clone()).or_default().push((v.clone(), seq));
        }
    }
    fn durable(&mut self, seq: u64, rows: &[(Vec<u8>, Vec<u8>)]) {
        for (k, v) in rows {
            self.known.insert(k.clone(), (v.clone(), seq));
            if let Some(u) = self.unknown.get_mut(k) {
                u.retain(|(_, s)| *s > seq);
            }
        }
        self.durable.push((seq, rows.to_vec()));
    }
    fn never(&mut self, seq: u64, rows: &[(Vec<u8>, Vec<u8>)], why: &'static str) {
        for (k, v) in rows {
            if let Some(u) = self.unknown.get_mut(k) {
                u.retain(|(_, s)| *s != seq);
            }
            self.dead.push((k.clone(), v.clone(), seq, why));
        }
    }
    /// What a read of `row` at the latest snapshot may return.
    fn allowed(&self, row: &[u8]) -> Vec<Option<Vec<u8>>> {
        let mut out = vec![self.known.get(row).map(|(v, _)| v.clone())];
        for (v, _) in self.unknown.get(row).into_iter().flatten() {
            out.push(Some(v.clone()));
        }
        out
    }
    fn check_latest(&self, row: &[u8], got: Option<&[u8]>) -> Result<(), String> {
        let allowed = self.allowed(row);
        if allowed.iter().any(|a| a.as_deref() == got) {
            return Ok(());
        }
        let who = self
            .dead
            .iter()
            .find(|(k, v, _, _)| k == row && Some(v.as_slice()) == got)
            .map(|(_, _, s, why)| format!(" -- that is commit {s}, which the client was told {why}"))
            .unwrap_or_default();
        Err(format!(
            "row {:?} reads {:?}{who}; allowed: {:?}",
            String::from_utf8_lossy(row),
            got.map(String::from_utf8_lossy),
            allowed.iter().map(|a| a.as_deref().map(String::from_utf8_lossy)).collect::<Vec<_>>()
        ))
    }
}

/// Why a seed's run phase stopped before its steps ran out.
enum End {
    Violation(String),
    /// A designed fatal or an unopenable bucket: the process is gone.
    Dead,
}

struct Run<'a> {
    b: &'a Bucket,
    seed: u64,
    rng: XorShift,
    model: Model,
    d: Option<Db>,
    step: u64,
}

const ROWS: u64 = 24;

impl<'a> Run<'a> {
    fn value(&self, i: u64) -> Vec<u8> {
        format!("{}:{}:{i}", self.seed, self.step).into_bytes()
    }

    fn random_rows(&mut self, i: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let n = 1 + self.rng.below(3);
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for _ in 0..n {
            let r = self.rng.below(ROWS);
            rows.insert(row(r), self.value(i));
        }
        rows.into_iter().collect()
    }

    /// Reopens after a crash, a fence, or a designed fatal. The AM's server
    /// is restarted by the postmaster and opens again; a bucket that will
    /// not open is a dead cluster.
    fn reopen(&mut self) -> Result<(), End> {
        self.d = None;
        self.model.stats.reopens += 1;
        for _ in 0..5 {
            match catch_unwind(AssertUnwindSafe(|| self.b.open())) {
                Ok(Ok(d)) => {
                    self.d = Some(d);
                    return Ok(());
                }
                Ok(Err(_)) => self.model.stats.open_errs += 1,
                Err(p) => {
                    let msg = panic_message(p);
                    if is_designed_fatal(&msg) {
                        self.model.stats.designed_fatals += 1;
                    } else {
                        return Err(End::Violation(format!("open panicked: {msg}")));
                    }
                }
            }
        }
        Err(End::Dead)
    }

    /// One transaction group: one to three commits staged and flown as one
    /// object, each then confirmed or aborted as Postgres would.
    fn transact(&mut self) -> Result<(), End> {
        let sync = !self.rng.chance(0.1);
        let members = 1 + self.rng.below(3);
        let s = Arc::clone(&self.b.store);
        let mut staged: Vec<(u64, u64, Vec<(Vec<u8>, Vec<u8>)>)> = Vec::new();
        for i in 0..members {
            let rows = self.random_rows(i);
            let d = self.d.as_mut().unwrap();
            match d.stage_commit(writes(&rows), self.step as u32, LATEST, sync) {
                Ok(Ok(Some((t, seq)))) => {
                    self.model.begin(seq, &rows);
                    if !sync {
                        d.mark_confirmed(seq); // acknowledged before the write
                    }
                    staged.push((t, seq, rows));
                }
                Ok(Ok(None)) => return Err(End::Violation("empty commit staged".into())),
                Ok(Err(c)) => return Err(End::Violation(format!("conflict at LATEST: {c:?}"))),
                Err(_) => {
                    // Fenced or lease gone: the server restarts.
                    return self.reopen();
                }
            }
        }
        // An abort before the write: nothing was ever sent.
        if sync && self.rng.chance(0.05) {
            let (_, seq, rows) = staged.remove(self.rng.below(staged.len() as u64) as usize);
            let d = self.d.as_mut().unwrap();
            match d.begin_discard(seq, Discard::Aborted) {
                None => {
                    self.model.never(seq, &rows, "aborted before its write");
                    self.model.stats.aborted_unwritten += 1;
                }
                Some(m) => return Err(End::Violation(format!("a marker for an unwritten commit: {m:?}"))),
            }
        }
        let abort_after = sync && self.rng.chance(0.1);
        let d = self.d.as_mut().unwrap();
        // The writer thread. A marker that will not write is a designed
        // fatal inside `flight_failed`.
        let flown = catch_unwind(AssertUnwindSafe(|| fly(d, &s)));
        if let Err(p) = flown {
            return self.fatal(panic_message(p));
        }
        for (t, seq, rows) in staged {
            let d = self.d.as_mut().unwrap();
            match d.take_outcome(t) {
                Some(Outcome::Durable(x)) => {
                    if x != seq {
                        return Err(End::Violation(format!("Durable({x}) for a commit staged at {seq}")));
                    }
                    if abort_after {
                        // Postgres aborts after pre-commit; the object is in
                        // the bucket.
                        let Some(m) = d.begin_discard(seq, Discard::Aborted) else {
                            return Err(End::Violation(format!("no marker owed for landed commit {seq}")));
                        };
                        match m.write(&s) {
                            Ok(()) => {
                                d.discard_written(m);
                                self.model.never(seq, &rows, "aborted after its object landed");
                                self.model.stats.aborted += 1;
                            }
                            Err(e) => {
                                let r = catch_unwind(AssertUnwindSafe(|| d.discard_failed(&m, &e)));
                                let msg = panic_message(r.expect_err("discard_failed does not return"));
                                return self.fatal(msg);
                            }
                        }
                    } else {
                        if sync {
                            d.mark_confirmed(seq);
                            self.model.stats.commits_ok += 1;
                        } else {
                            self.model.stats.async_ok += 1;
                        }
                        self.model.durable(seq, &rows);
                    }
                }
                Some(Outcome::Failed(_)) => {
                    if !sync {
                        return Err(End::Violation(format!("an acknowledged asynchronous commit {seq} told Failed")));
                    }
                    self.model.never(seq, &rows, "failed");
                    self.model.stats.failed += 1;
                }
                Some(Outcome::Fenced(_)) => {
                    // Unknown: the object may be there. An asynchronous
                    // commit here was acknowledged and may now be lost --
                    // the loss the caller of `sync = false` accepted.
                    self.model.stats.fenced += 1;
                    if !sync {
                        self.model.stats.async_lost += 1;
                    }
                }
                Some(Outcome::Refused(c)) => return Err(End::Violation(format!("Refused({c:?}) is reserved"))),
                None => self.model.stats.no_outcome += 1,
            }
        }
        if self.d.as_ref().unwrap().is_fenced() {
            return self.reopen();
        }
        Ok(())
    }

    fn fatal(&mut self, msg: String) -> Result<(), End> {
        if !is_designed_fatal(&msg) {
            return Err(End::Violation(format!("panic: {msg}")));
        }
        self.model.stats.designed_fatals += 1;
        // The process died; whatever was pending is unknown. Restart.
        self.reopen()
    }

    fn compact(&mut self) -> Result<(), End> {
        let d = self.d.as_mut().unwrap();
        let horizon = if self.rng.chance(0.5) { 0 } else { d.current_seq().saturating_sub(self.rng.below(8)) };
        let s = Arc::clone(&self.b.store);
        let mut collected = self.model.collected;
        let r = catch_unwind(AssertUnwindSafe(|| fold(d, &s, horizon, &mut collected)));
        self.model.collected = collected;
        match r {
            Ok(Ok(true)) => self.model.stats.folds += 1,
            Ok(Ok(false)) => {}
            Ok(Err(_)) => self.model.stats.fold_errs += 1,
            Err(p) => return self.fatal(panic_message(p)),
        }
        Ok(())
    }

    fn read(&mut self) -> Result<(), End> {
        let r = row(self.rng.below(ROWS));
        let d = self.d.as_ref().unwrap();
        match catch_unwind(AssertUnwindSafe(|| d.get(&r))) {
            Ok(Ok(got)) => {
                self.model.stats.reads_ok += 1;
                self.model.check_latest(&r, got.as_deref()).map_err(|e| End::Violation(format!("read during the run: {e}")))
            }
            Ok(Err(_)) => {
                self.model.stats.read_errs += 1;
                Ok(())
            }
            Err(p) => Err(End::Violation(format!("read panicked: {}", panic_message(p)))),
        }
    }

    fn step(&mut self) -> Result<(), End> {
        self.step += 1;
        if self.d.is_none() {
            self.reopen()?;
        }
        let roll = self.rng.below(100);
        match roll {
            0..=77 => self.transact(),
            78..=86 => self.compact(),
            87..=95 => self.read(),
            _ => self.reopen(),
        }
    }

    /// The bucket as a fresh, fault-free open sees it, against the model.
    fn verify(&mut self) -> Result<(), String> {
        self.d = None;
        self.b.faults.set_enabled(false);
        let r = match catch_unwind(AssertUnwindSafe(|| self.b.open())) {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                if self.b.faults.torn_keys().is_empty() {
                    return Err(format!("the bucket does not open and holds no torn object: {e}"));
                }
                self.model.stats.unopenable_torn += 1;
                return Ok(());
            }
            Err(p) => return Err(format!("open panicked: {}", panic_message(p))),
        };
        for i in 0..ROWS {
            let k = row(i);
            let got = r.get(&k).map_err(|e| format!("read of {:?} failed with faults off: {e}", String::from_utf8_lossy(&k)))?;
            self.model.check_latest(&k, got.as_deref()).map_err(|e| format!("after reopen: {e}"))?;
        }
        // What the bucket says was collected, or what the compactor asked
        // for, whichever is higher: a horizon marker whose PUT failed leaves
        // the bucket saying less than the run it holds has dropped.
        let floor = r.collected_through().max(self.model.collected);
        for (seq, rows) in &self.model.durable {
            if *seq <= floor {
                continue; // history there was collected, by design
            }
            for (k, v) in rows {
                let got = r.get_at(k, *seq).map_err(|e| format!("read at {seq} failed: {e}"))?;
                if got.as_ref() != Some(v) {
                    return Err(format!(
                        "commit {seq} was told durable but row {:?} at {seq} reads {:?}, not {:?}",
                        String::from_utf8_lossy(k),
                        got.as_deref().map(String::from_utf8_lossy),
                        String::from_utf8_lossy(v)
                    ));
                }
            }
        }
        for (k, v, seq, why) in &self.model.dead {
            if *seq <= floor {
                continue;
            }
            let got = r.get_at(k, *seq).map_err(|e| format!("read at {seq} failed: {e}"))?;
            if got.as_ref() == Some(v) {
                return Err(format!(
                    "commit {seq} was told `{why}` but row {:?} at {seq} reads its value {:?}",
                    String::from_utf8_lossy(k),
                    String::from_utf8_lossy(v)
                ));
            }
        }
        Ok(())
    }
}

/// Runs one seed: `steps` operations under `rate` random faults of the
/// given kinds, then a verification with the faults off.
fn mixed(seed: u64, steps: u64, rate: f64, kinds: &[Fault]) -> Result<Stats, String> {
    let b = bucket(seed);
    let mut run = Run { b: &b, seed, rng: XorShift::new(seed ^ 0xA5A5_5A5A), model: Model::default(), d: None, step: 0 };
    // Faults from the first open on: a restart into a bad network is a
    // restart too.
    b.faults.set_random(rate, kinds);
    let mut end = None;
    for _ in 0..steps {
        match run.step() {
            Ok(()) => {}
            Err(End::Violation(v)) => {
                end = Some(v);
                break;
            }
            Err(End::Dead) => break,
        }
    }
    if let Some(v) = end {
        return Err(b.failure(seed, &format!("during the run (step {}): {v}", run.step)));
    }
    run.verify().map_err(|v| b.failure(seed, &v))?;
    run.model.stats.faults = b.faults.faults_injected();
    Ok(run.model.stats)
}

#[test]
fn random_faults_on_every_operation_keep_what_clients_were_told() {
    // Every kind, a stale LIST included: the open probes past what a
    // listing shows wherever an omission would cost a commit (see
    // `a_stale_list_at_open_...` below).
    let kinds = Fault::all();
    let mut total = Stats::default();
    for seed in 0..SEEDS {
        let stats = mixed(seed, 500, 0.05, &kinds).unwrap_or_else(|e| panic!("{e}"));
        total.add(&stats);
    }
    eprintln!("mixed faults, {SEEDS} seeds: {total:#?}");
    assert!(total.faults > 0);
    assert!(total.commits_ok > 0 && total.failed > 0 && total.fenced > 0, "{total:?}");
    assert!(total.folds > 0 && total.reopens > 0 && total.designed_fatals > 0, "{total:?}");
    assert!(total.aborted > 0 && total.reads_ok > 0, "{total:?}");
}

// ---- 5. the horizon marker does not write -----------------------------------

/// A fold drops history at or below its horizon into the run it writes, and
/// then publishes the horizon so a restart refuses reads below it. If the
/// marker's PUT fails the run is still there with its history gone, and
/// the next open answers reads below the horizon from what is left --
/// fewer rows, nothing reported wrong. Only reads at old snapshots after a
/// restart can see it, which Postgres never asks for.
#[test]
fn an_unpublished_horizon_is_refused_not_answered_short_after_a_restart() {
    for seed in 0..20 {
        let b = bucket(seed);
        let mut d = b.open().unwrap();
        for i in 1..=5 {
            commit(&mut d, &b.store, one(b"row", format!("v{i}").as_bytes()), i);
        }
        let how = if seed % 2 == 0 { Fault::ErrBeforeLanded } else { Fault::PhantomExists };
        b.faults.add_rule(Rule::every(OpKind::Put, "horizon/", how));
        assert!(fold(&mut d, &b.store, 5, &mut 0).unwrap());
        assert_eq!(d.collected_through(), 5, "in memory the bar is raised");
        assert!(d.get_at(b"row", 1).is_err(), "and a read below it is refused while the process lives");
        drop(d);
        b.faults.set_enabled(false);
        let r = b.open().unwrap();
        let got = r.get_at(b"row", 1);
        assert!(
            got.is_err(),
            "{}",
            b.failure(seed, &format!("after a restart the read at 1 answers {:?} instead of refusing", got.map(|v| v.map(|v| String::from_utf8_lossy(&v).into_owned()))))
        );
    }
}

// ---- 6. a listing that has not caught up ----------------------------------

/// One stale `LIST commit/` at a restart. The open numbers from what it
/// listed, so the next commit takes the number of an acknowledged commit
/// it did not see; the collision fences the new writer, and the takeover
/// fence then judges the older, acknowledged object a stale writer's.
#[test]
fn a_stale_list_at_open_does_not_lose_an_acknowledged_commit() {
    for seed in 0..20 {
        let b = bucket(seed);
        let mut d = b.open().unwrap();
        let n = 3 + seed % 4;
        let mut told = Vec::new();
        for i in 0..n {
            let v = format!("v{seed}-{i}").into_bytes();
            let seq = commit(&mut d, &b.store, one(&row(i), &v), i as u32);
            told.push((seq, row(i), v));
        }
        drop(d);
        b.faults.add_rule(Rule::nth(OpKind::List, "commit/", 1, Fault::ListStale(1)));
        let mut d = b.open().unwrap();
        let (t, seq) = d.stage_commit(one(b"after", b"1"), 99, LATEST, true).unwrap().unwrap().unwrap();
        fly(&mut d, &b.store);
        let after = d.take_outcome(t);
        if let Some(Outcome::Durable(_)) = after {
            d.mark_confirmed(seq);
        }
        drop(d);
        b.faults.set_enabled(false);
        let r = b.open().unwrap();
        for (seq, k, v) in told {
            assert_eq!(
                r.get(&k).unwrap(),
                Some(v),
                "{}",
                b.failure(seed, &format!("commit {seq} was told Durable before the restart and is gone after it (new writer's outcome: {after:?})"))
            );
        }
    }
}
