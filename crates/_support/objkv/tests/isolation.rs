//! A concurrent isolation checker in the style of Jepsen's Elle
//! (list-append), run against the engine's public API.
//!
//! The model is N keys, each holding a list of transaction ids encoded as
//! little-endian u32s. A transaction takes a snapshot, reads some keys at it,
//! appends its own id to some of the keys it read (read-modify-write, as an
//! application would), and commits through exactly the protocol the table AM
//! drives (`crates/backend/access/table/tableam/src/objkv_am.rs`):
//!
//! * snapshot: `(current_seq(), view())` under one lock hold (objkv_am.rs:250)
//! * reads: through that view, at that number, with no lock held
//! * commit: a fresh view's `find_run_conflict(writes, S)` off-lock, then
//!   `stage_commit_checked(writes, xid, S, sync, probed_base)` under the lock
//!   (objkv_am.rs:838-859)
//! * writer: `take_flight` under the lock, PUT without it, `flight_written`
//!   under it (objkv_am.rs:723-740); a synchronous transaction waits with
//!   `take_outcome` (objkv_am.rs:773)
//! * commit in Postgres: `mark_confirmed(seq)` (objkv_am.rs:604); an
//!   asynchronous commit confirms before its object lands
//! * abort after the object landed: `begin_discard` under the lock, the
//!   marker PUT without it, `discard_written` under it (objkv_am.rs:809-812)
//! * compactor: `fold_plan` under the lock, `build_fold`/`put_fold` without,
//!   `apply_fold` under, `execute_sweep` without, `sweep_done` under
//!   (objkv_am.rs:680-711), with the collection horizon
//!   `now - retain` capped by the oldest snapshot in use (objkv_am.rs:307)
//!
//! Every transaction records its snapshot, what it read, what it wrote and
//! how it ended; the checker runs over that history afterwards. Two drivers
//! share the transaction state machine: real threads over one
//! `Arc<Mutex<Db>>`, as the server has, and a deterministic scheduler that
//! interleaves the same steps by seed so a failing seed reproduces exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use objkv::commit::Op;
use objkv::db::{
    self, Db, Discard, FoldPlan, Folded, Outcome, SweepPlan, View,
};
use objkv::key::LATEST;
use objkv::s3::PutOutcome;

/// A deliberate break in the protocol, to prove the checker notices. The
/// oracle is only worth something if it fires on the bugs it exists for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    None,
    /// Validate against `LATEST`: no first-committer-wins at all.
    ValidateAtLatest,
    /// Take the snapshot one above the decided prefix -- the definition the
    /// review found: a number handed out but not yet confirmed sits below
    /// commits the reader can see, and a write validated against it never
    /// meets that number's writes.
    SnapshotAboveDecided,
}
use objkv::store::{MemStore, Store};

// ---------------------------------------------------------------------------
// A small deterministic PRNG (xorshift64*).

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        // Splitmix the seed so that neighbouring seeds do not share a prefix.
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Rng(z | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        self.next() % n
    }
    fn pct(&mut self, p: u64) -> bool {
        self.below(100) < p
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

// ---------------------------------------------------------------------------
// The model's encoding.

fn key_bytes(k: usize) -> Vec<u8> {
    format!("k/{k:03}").into_bytes()
}

fn encode(list: &[u32]) -> Vec<u8> {
    list.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn decode(v: Option<Vec<u8>>) -> Vec<u32> {
    match v {
        None => Vec::new(),
        Some(b) => {
            assert!(b.len() % 4 == 0, "value of {} bytes is not a list", b.len());
            b.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
        }
    }
}

fn txn_id(worker: usize, n: usize) -> u32 {
    ((worker as u32) << 24) | (n as u32)
}

fn tname(id: u32) -> String {
    format!("T{}.{}", id >> 24, id & 0x00FF_FFFF)
}

fn lname(list: &[u32]) -> String {
    let names: Vec<String> = list.iter().map(|&id| tname(id)).collect();
    format!("[{}]", names.join(","))
}

// ---------------------------------------------------------------------------
// Configuration, derived from the seed.

#[derive(Clone, Debug)]
struct Config {
    seed: u64,
    workers: usize,
    txns_per_worker: usize,
    keys: usize,
    /// Commits of history kept below the present; 0 keeps everything, as
    /// `pgrust.objkv_retain_commits = 0` does.
    retain: u64,
    /// The compactor folds once this many commits sit above the base run.
    fold_after: usize,
    /// Percent of transactions committed asynchronously (confirmed before
    /// the object lands).
    async_pct: u64,
    /// Percent of flights whose `flight_written` the writer delays, so a
    /// staged-but-unconfirmed number exists while others take snapshots.
    defer_pct: u64,
    voluntary_abort_pct: u64,
    late_abort_pct: u64,
    inflight_abort_pct: u64,
    reread_pct: u64,
    readonly_pct: u64,
    mutation: Mutation,
}

fn config(seed: u64, txns_per_worker: usize) -> Config {
    let mut r = Rng::new(seed ^ 0xC0FF_EE00);
    Config {
        seed,
        workers: 4,
        txns_per_worker,
        keys: *r.pick(&[2, 3, 5, 8, 12, 20]),
        retain: *r.pick(&[0, 0, 2, 10, 50]),
        fold_after: *r.pick(&[1, 3, 10, 30, db::COMPACT_AFTER_COMMITS]),
        async_pct: *r.pick(&[0, 0, 20, 50]),
        defer_pct: *r.pick(&[0, 20, 50]),
        voluntary_abort_pct: 5,
        late_abort_pct: 5,
        inflight_abort_pct: 20,
        reread_pct: 25,
        readonly_pct: 10,
        mutation: Mutation::None,
    }
}

// ---------------------------------------------------------------------------
// The recorded history.

#[derive(Debug, Clone, PartialEq)]
enum Fate {
    Committed { seq: u64, sync: bool },
    /// Wrote nothing, so nothing was staged.
    ReadOnly,
    /// Aborted before pre-commit: nothing was staged.
    Voluntary,
    /// First-committer-wins refused it, in the run probe or under the lock.
    Conflict { key: usize, by: u64, at: &'static str },
    /// The object landed; then Postgres aborted; a discard marker was written.
    AbortedAfterLanded { seq: u64 },
    /// Asynchronous: staged, then aborted before it was confirmed.
    AbortedInFlight { seq: u64 },
    /// The engine reported a failure on a store that cannot fail.
    Failed(String),
}

#[derive(Debug, Clone)]
struct Txn {
    id: u32,
    snapshot: u64,
    /// In the order performed; a key may appear twice.
    reads: Vec<(usize, Vec<u32>)>,
    writes: Vec<usize>,
    fate: Fate,
}

impl Txn {
    fn describe(&self) -> String {
        let reads: Vec<String> =
            self.reads.iter().map(|(k, l)| format!("k{k:03}={}", lname(l))).collect();
        let writes: Vec<String> = self.writes.iter().map(|k| format!("k{k:03}")).collect();
        let fate = match &self.fate {
            Fate::Committed { seq, sync } => {
                format!("committed@{seq}{}", if *sync { "" } else { " (async)" })
            }
            Fate::ReadOnly => "read-only".to_string(),
            Fate::Voluntary => "aborted (voluntary, nothing staged)".to_string(),
            Fate::Conflict { key, by, at } => format!("conflict on k{key:03} by seq {by} at {at}"),
            Fate::AbortedAfterLanded { seq } => format!("aborted after landing@{seq} (marker)"),
            Fate::AbortedInFlight { seq } => format!("aborted in flight@{seq}"),
            Fate::Failed(w) => format!("FAILED: {w}"),
        };
        format!(
            "{:<8} S={:<5} reads{{{}}} writes{{{}}} => {}",
            tname(self.id),
            self.snapshot,
            reads.join(" "),
            writes.join(" "),
            fate
        )
    }
}

// ---------------------------------------------------------------------------
// The shared environment: one Db under one lock, as the server has.

struct Env {
    cfg: Config,
    db: Mutex<Db>,
    store: Arc<dyn Store>,
    /// Writer wake-up and outcome wait, as `SIGNAL` in the AM.
    signal: (Mutex<()>, Condvar),
    /// The oldest snapshot each worker reads at, as `IN_USE` in the AM.
    in_use: Mutex<BTreeMap<usize, u64>>,
    done_workers: AtomicUsize,
}

impl Env {
    fn new(cfg: Config) -> (Env, Arc<MemStore>) {
        let mem = Arc::new(MemStore::new());
        let store: Arc<dyn Store> = Arc::clone(&mem) as Arc<dyn Store>;
        let db = Db::open(Arc::clone(&store)).expect("open on a MemStore");
        let env = Env {
            cfg,
            db: Mutex::new(db),
            store,
            signal: (Mutex::new(()), Condvar::new()),
            in_use: Mutex::new(BTreeMap::new()),
            done_workers: AtomicUsize::new(0),
        };
        (env, mem)
    }

    fn db(&self) -> MutexGuard<'_, Db> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify(&self) {
        let _g = self.signal.0.lock().unwrap_or_else(|e| e.into_inner());
        self.signal.1.notify_all();
    }

    fn wait(&self, d: Duration) {
        let g = self.signal.0.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.signal.1.wait_timeout(g, d);
    }

    // objkv_am.rs:169-198.
    fn note_in_use(&self, worker: usize, seq: u64) {
        let mut m = self.in_use.lock().unwrap();
        let e = m.entry(worker).or_insert(u64::MAX);
        *e = (*e).min(seq);
    }
    fn release_in_use(&self, worker: usize) {
        self.in_use.lock().unwrap().remove(&worker);
    }
    fn oldest_in_use(&self) -> u64 {
        self.in_use.lock().unwrap().values().copied().min().unwrap_or(u64::MAX)
    }

    /// objkv_am.rs:307 `collection_horizon`.
    fn horizon(&self, now: u64) -> u64 {
        if self.cfg.retain == 0 {
            return 0;
        }
        now.saturating_sub(self.cfg.retain).min(self.oldest_in_use())
    }

    /// objkv_am.rs:809-816 `discard_commit`.
    fn discard(&self, seq: u64) {
        let marker = self.db().begin_discard(seq, Discard::Aborted);
        if let Some(m) = marker {
            m.write(&self.store).expect("marker PUT on a MemStore");
            self.db().discard_written(m);
        }
    }
}

// ---------------------------------------------------------------------------
// One transaction as a state machine, so both drivers can interleave it.

struct Plan {
    reads: Vec<usize>,
    writes: Vec<usize>,
    voluntary: bool,
    late_abort: bool,
    inflight_abort: bool,
    sync: bool,
}

fn plan(cfg: &Config, r: &mut Rng) -> Plan {
    let nread = 1 + r.below(3.min(cfg.keys as u64)) as usize;
    let mut reads: Vec<usize> = Vec::new();
    while reads.len() < nread {
        let k = r.below(cfg.keys as u64) as usize;
        if !reads.contains(&k) {
            reads.push(k);
        }
    }
    let nwrite = if r.pct(cfg.readonly_pct) { 0 } else { 1 + r.below(2.min(nread as u64)) as usize };
    let writes = reads[..nwrite].to_vec();
    if r.pct(cfg.reread_pct) {
        let again = reads[r.below(nread as u64) as usize];
        reads.push(again);
    }
    let sync = !r.pct(cfg.async_pct);
    Plan {
        reads,
        writes,
        voluntary: r.pct(cfg.voluntary_abort_pct),
        late_abort: r.pct(cfg.late_abort_pct),
        inflight_abort: !sync && r.pct(cfg.inflight_abort_pct),
        sync,
    }
}

enum Phase {
    Start,
    Reading { view: View, next: usize },
    Deciding,
    Staged { ticket: u64, seq: u64 },
    Done,
}

enum Progress {
    Continue,
    Waiting,
    Done,
}

struct Live {
    worker: usize,
    plan: Plan,
    phase: Phase,
    rec: Txn,
}

impl Live {
    fn new(worker: usize, n: usize, plan: Plan) -> Live {
        let id = txn_id(worker, n);
        Live {
            worker,
            plan,
            phase: Phase::Start,
            rec: Txn { id, snapshot: 0, reads: Vec::new(), writes: Vec::new(), fate: Fate::ReadOnly },
        }
    }

    fn finish(&mut self, env: &Env, fate: Fate) -> Progress {
        self.rec.fate = fate;
        self.phase = Phase::Done;
        env.release_in_use(self.worker);
        Progress::Done
    }

    fn step(&mut self, env: &Env) -> Progress {
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Start => {
                // objkv_am.rs:250: the number and the view under one lock hold.
                let (mut seq, view) = {
                    let d = env.db();
                    (d.current_seq(), d.view())
                };
                if env.cfg.mutation == Mutation::SnapshotAboveDecided {
                    seq += 1;
                }
                env.note_in_use(self.worker, seq);
                self.rec.snapshot = seq;
                self.phase = Phase::Reading { view, next: 0 };
                Progress::Continue
            }
            Phase::Reading { view, next } => {
                let k = self.plan.reads[next];
                let got = view.get_at(&key_bytes(k), self.rec.snapshot).expect("read on a MemStore");
                self.rec.reads.push((k, decode(got)));
                self.phase = if next + 1 < self.plan.reads.len() {
                    Phase::Reading { view, next: next + 1 }
                } else {
                    Phase::Deciding
                };
                Progress::Continue
            }
            Phase::Deciding => {
                if self.plan.writes.is_empty() {
                    return self.finish(env, Fate::ReadOnly);
                }
                if self.plan.voluntary {
                    return self.finish(env, Fate::Voluntary);
                }
                // Read-modify-write: append to the list as this transaction saw it.
                let mut writes: BTreeMap<Vec<u8>, Op> = BTreeMap::new();
                for &k in &self.plan.writes {
                    let base = self
                        .rec
                        .reads
                        .iter()
                        .rev()
                        .find(|(rk, _)| *rk == k)
                        .map(|(_, l)| l.clone())
                        .expect("every written key was read");
                    let mut list = base;
                    list.push(self.rec.id);
                    writes.insert(key_bytes(k), Op::Put(encode(&list)));
                }
                self.rec.writes = self.plan.writes.clone();
                let snap = match env.cfg.mutation {
                    Mutation::ValidateAtLatest => LATEST,
                    _ => self.rec.snapshot,
                };
                // objkv_am.rs:838-848: the run half of validation through a
                // fresh view, no lock held.
                let probe = env.db().view();
                let probed_base = probe.base_run_id();
                if let Some(c) = probe.find_run_conflict(&writes, snap).expect("probe on a MemStore") {
                    let key = key_index(&c.key);
                    return self.finish(env, Fate::Conflict { key, by: c.by, at: "probe" });
                }
                drop(probe);
                // objkv_am.rs:857-859: the in-memory half, under the lock.
                let staged = env
                    .db()
                    .stage_commit_checked(writes, self.rec.id, snap, self.plan.sync, probed_base)
                    .expect("stage on a MemStore");
                let (ticket, seq) = match staged {
                    Err(c) => {
                        let key = key_index(&c.key);
                        return self.finish(env, Fate::Conflict { key, by: c.by, at: "stage" });
                    }
                    Ok(None) => unreachable!("non-empty writes staged nothing"),
                    Ok(Some(x)) => x,
                };
                env.notify();
                if !self.plan.sync {
                    // An asynchronous commit does not wait for the PUT: the
                    // transaction commits in Postgres and `mark_confirmed`
                    // runs at once (objkv_am.rs:604), or it aborts and
                    // discards (objkv_am.rs:593).
                    if self.plan.inflight_abort {
                        env.discard(seq);
                        return self.finish(env, Fate::AbortedInFlight { seq });
                    }
                    env.db().mark_confirmed(seq);
                    return self.finish(env, Fate::Committed { seq, sync: false });
                }
                self.phase = Phase::Staged { ticket, seq };
                Progress::Continue
            }
            Phase::Staged { ticket, seq } => {
                // objkv_am.rs:773 `wait_outcome`.
                let outcome = env.db().take_outcome(ticket);
                match outcome {
                    None => {
                        self.phase = Phase::Staged { ticket, seq };
                        Progress::Waiting
                    }
                    Some(Outcome::Durable(landed)) => {
                        if landed != seq {
                            return self.finish(
                                env,
                                Fate::Failed(format!("staged at {seq} but durable at {landed}")),
                            );
                        }
                        if self.plan.late_abort {
                            // OBJKV_FAULT_ERROR_AFTER_COMMIT_PUT's path:
                            // the object landed, Postgres aborts.
                            env.discard(seq);
                            return self.finish(env, Fate::AbortedAfterLanded { seq });
                        }
                        env.db().mark_confirmed(seq);
                        self.finish(env, Fate::Committed { seq, sync: true })
                    }
                    Some(Outcome::Refused(c)) => {
                        self.finish(env, Fate::Failed(format!("Outcome::Refused({c:?}) is never produced")))
                    }
                    Some(Outcome::Failed(w)) | Some(Outcome::Fenced(w)) => {
                        self.finish(env, Fate::Failed(w))
                    }
                }
            }
            Phase::Done => Progress::Done,
        }
    }
}

fn key_index(k: &[u8]) -> usize {
    std::str::from_utf8(k)
        .ok()
        .and_then(|s| s.strip_prefix("k/"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX)
}

// ---------------------------------------------------------------------------
// The writer (objkv_am.rs:715-761), with optional delayed landings.

struct Writer {
    rng: Rng,
    /// Flights whose PUT is done but whose `flight_written` is held back:
    /// (first seq, tick at which to land).
    in_air: Vec<(u64, u64)>,
    tick: u64,
}

impl Writer {
    fn new(rng: Rng) -> Writer {
        Writer { rng, in_air: Vec::new(), tick: 0 }
    }

    /// One flight: taken under the lock, PUT without it, reported under it.
    fn fly_one(&mut self, env: &Env) -> bool {
        let Some(f) = env.db().take_flight() else { return false };
        match env.store.put_if_absent(&f.key, &f.bytes).expect("PUT on a MemStore") {
            PutOutcome::Written => {
                if self.rng.pct(env.cfg.defer_pct) {
                    let due = self.tick + 1 + self.rng.below(3);
                    self.in_air.push((f.first, due));
                } else {
                    env.db().flight_written(f.first);
                }
            }
            PutOutcome::AlreadyExists => env.db().flight_lost(&f).expect("flight_lost"),
        }
        true
    }

    fn land(&mut self, env: &Env, idx: usize) {
        let (first, _) = self.in_air.remove(idx);
        env.db().flight_written(first);
    }

    fn land_due(&mut self, env: &Env) -> bool {
        let mut did = false;
        while let Some(i) = self.in_air.iter().position(|&(_, due)| due <= self.tick) {
            self.land(env, i);
            did = true;
        }
        did
    }

    /// The deterministic driver's step: land a held flight or fly one.
    fn step(&mut self, env: &Env) -> bool {
        self.tick += 1;
        if !self.in_air.is_empty() && self.rng.pct(34) {
            let i = self.rng.below(self.in_air.len() as u64) as usize;
            self.land(env, i);
            return true;
        }
        if self.fly_one(env) {
            return true;
        }
        if !self.in_air.is_empty() {
            let i = self.rng.below(self.in_air.len() as u64) as usize;
            self.land(env, i);
            return true;
        }
        false
    }

    /// The threaded driver's loop.
    fn run(mut self, env: &Env) {
        loop {
            self.tick += 1;
            let mut did = self.fly_one(env);
            did |= self.land_due(env);
            if did {
                env.notify();
                continue;
            }
            let done = env.done_workers.load(Ordering::Acquire) == env.cfg.workers;
            let owed = env.db().has_unwritten();
            if done && !owed && self.in_air.is_empty() {
                return;
            }
            // A held flight leaves its number staged-but-unconfirmed while
            // the others run; a short wait keeps that window real.
            let d = if self.in_air.is_empty() { Duration::from_millis(1) } else { Duration::from_micros(100) };
            env.wait(d);
        }
    }
}

// ---------------------------------------------------------------------------
// The compactor (objkv_am.rs:672-712).

enum Comp {
    Idle,
    Planned { plan: FoldPlan, horizon: u64 },
    Built { plan: FoldPlan, folded: Folded, horizon: u64 },
    Applied { sweep: SweepPlan },
}

struct Compactor {
    state: Comp,
    folds: usize,
}

impl Compactor {
    fn new() -> Compactor {
        Compactor { state: Comp::Idle, folds: 0 }
    }

    fn is_idle(&self) -> bool {
        matches!(self.state, Comp::Idle)
    }

    fn step(&mut self, env: &Env) -> bool {
        self.state = match std::mem::replace(&mut self.state, Comp::Idle) {
            Comp::Idle => {
                let d = env.db();
                if d.commit_backlog() < env.cfg.fold_after {
                    return false;
                }
                let Some(plan) = d.fold_plan() else { return false };
                let now = d.current_seq();
                drop(d);
                let horizon = env.horizon(now);
                Comp::Planned { plan, horizon }
            }
            Comp::Planned { plan, horizon } => {
                let folded = db::build_fold(&plan, horizon, &BTreeMap::new()).expect("build_fold");
                db::put_fold(&env.store, &folded).expect("put_fold");
                Comp::Built { plan, folded, horizon }
            }
            Comp::Built { plan, folded, horizon } => {
                let sweep = env.db().apply_fold(plan, &folded, horizon).expect("apply_fold");
                Comp::Applied { sweep }
            }
            Comp::Applied { sweep } => {
                let result = db::execute_sweep(&env.store, sweep);
                env.db().sweep_done(result);
                self.folds += 1;
                Comp::Idle
            }
        };
        true
    }

    fn run(mut self, env: &Env) -> usize {
        loop {
            if self.step(env) {
                continue;
            }
            if env.done_workers.load(Ordering::Acquire) == env.cfg.workers && self.is_idle() {
                return self.folds;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    }
}

// ---------------------------------------------------------------------------
// Drivers.

struct RunResult {
    cfg: Config,
    mode: &'static str,
    history: Vec<Txn>,
    db: Db,
    store: Arc<dyn Store>,
    folds: usize,
}

fn run_threaded(cfg: Config) -> RunResult {
    let (env, _mem) = Env::new(cfg.clone());
    let env = Arc::new(env);
    let mut handles = Vec::new();
    for w in 0..cfg.workers {
        let env = Arc::clone(&env);
        handles.push(std::thread::spawn(move || {
            let mut r = Rng::new(cfg.seed.wrapping_mul(7919) + w as u64);
            let mut out = Vec::with_capacity(env.cfg.txns_per_worker);
            for n in 0..env.cfg.txns_per_worker {
                let mut live = Live::new(w, n, plan(&env.cfg, &mut r));
                loop {
                    match live.step(&env) {
                        Progress::Continue => {
                            if r.pct(10) {
                                std::thread::yield_now();
                            }
                        }
                        Progress::Waiting => env.wait(Duration::from_millis(1)),
                        Progress::Done => break,
                    }
                }
                out.push(live.rec);
            }
            env.done_workers.fetch_add(1, Ordering::AcqRel);
            env.notify();
            out
        }));
    }
    let writer = {
        let env = Arc::clone(&env);
        let w = Writer::new(Rng::new(cfg.seed ^ 0x5757));
        std::thread::spawn(move || w.run(&env))
    };
    let compactor = {
        let env = Arc::clone(&env);
        std::thread::spawn(move || Compactor::new().run(&env))
    };
    let mut history = Vec::new();
    for h in handles {
        history.extend(h.join().expect("worker"));
    }
    writer.join().expect("writer");
    let folds = compactor.join().expect("compactor");
    let env = Arc::try_unwrap(env).ok().expect("every thread joined");
    let db = env.db.into_inner().unwrap_or_else(|e| e.into_inner());
    RunResult { cfg, mode: "threaded", history, db, store: env.store, folds }
}

fn run_scheduled(cfg: Config) -> RunResult {
    struct Worker {
        rng: Rng,
        next: usize,
        live: Option<Live>,
        out: Vec<Txn>,
    }
    let (env, _mem) = Env::new(cfg.clone());
    let mut workers: Vec<Worker> = (0..cfg.workers)
        .map(|w| Worker {
            rng: Rng::new(cfg.seed.wrapping_mul(7919) + w as u64),
            next: 0,
            live: None,
            out: Vec::new(),
        })
        .collect();
    let mut writer = Writer::new(Rng::new(cfg.seed ^ 0x5757));
    let mut comp = Compactor::new();
    let mut sched = Rng::new(cfg.seed ^ 0x5C5C);
    let mut steps = 0u64;
    loop {
        steps += 1;
        assert!(steps < 100_000_000, "seed {}: the scheduler did not converge", cfg.seed);
        let left: Vec<usize> = workers
            .iter()
            .enumerate()
            .filter(|(_, w)| w.live.is_some() || w.next < cfg.txns_per_worker)
            .map(|(i, _)| i)
            .collect();
        if left.is_empty() && writer.in_air.is_empty() && comp.is_idle() && !env.db().has_unwritten() {
            break;
        }
        // Weights: each worker 4, the writer 3, the compactor 1.
        let total = left.len() as u64 * 4 + 4;
        let pick = sched.below(total);
        if pick < left.len() as u64 * 4 {
            let w = &mut workers[left[(pick / 4) as usize]];
            if w.live.is_none() {
                let p = plan(&env.cfg, &mut w.rng);
                w.live = Some(Live::new(left[(pick / 4) as usize], w.next, p));
            }
            if let Progress::Done = w.live.as_mut().unwrap().step(&env) {
                w.out.push(w.live.take().unwrap().rec);
                w.next += 1;
            }
        } else if pick < left.len() as u64 * 4 + 3 {
            writer.step(&env);
        } else {
            comp.step(&env);
        }
    }
    let history: Vec<Txn> = workers.into_iter().flat_map(|w| w.out).collect();
    let db = env.db.into_inner().unwrap_or_else(|e| e.into_inner());
    RunResult { cfg, mode: "scheduled", history, db, store: env.store, folds: comp.folds }
}

// ---------------------------------------------------------------------------
// The checker.

struct Model {
    /// Per key: committed appends in commit-seq order.
    per_key: Vec<Vec<(u64, u32)>>,
    /// Commit seq of every committed transaction.
    seq_of: BTreeMap<u32, u64>,
    aborted: BTreeSet<u32>,
    snapshots: BTreeSet<u64>,
}

fn list_at(appends: &[(u64, u32)], s: u64) -> Vec<u32> {
    appends.iter().take_while(|(seq, _)| *seq <= s).map(|(_, id)| *id).collect()
}

fn build_model(cfg: &Config, history: &[Txn], out: &mut Vec<String>) -> Model {
    let mut per_key: Vec<Vec<(u64, u32)>> = vec![Vec::new(); cfg.keys];
    let mut seq_of = BTreeMap::new();
    let mut aborted = BTreeSet::new();
    let mut by_seq: BTreeMap<u64, u32> = BTreeMap::new();
    let mut snapshots = BTreeSet::new();
    for t in history {
        snapshots.insert(t.snapshot);
        match &t.fate {
            Fate::Committed { seq, .. } => {
                if let Some(other) = by_seq.insert(*seq, t.id) {
                    out.push(format!(
                        "two transactions committed at seq {seq}: {} and {}",
                        tname(other),
                        tname(t.id)
                    ));
                }
                if *seq <= t.snapshot {
                    out.push(format!("{} committed at {seq}, not above its snapshot {}", tname(t.id), t.snapshot));
                }
                seq_of.insert(t.id, *seq);
                for &k in &t.writes {
                    per_key[k].push((*seq, t.id));
                }
            }
            Fate::ReadOnly => {}
            Fate::Failed(w) => {
                aborted.insert(t.id);
                out.push(format!("{} failed on a MemStore: {w}", tname(t.id)));
            }
            _ => {
                aborted.insert(t.id);
            }
        }
    }
    for l in &mut per_key {
        l.sort_unstable();
    }
    Model { per_key, seq_of, aborted, snapshots }
}

fn explain_list(m: &Model, s: u64, obs: &[u32], exp: &[u32], final_list: &[u32]) -> Vec<String> {
    let mut why = Vec::new();
    for id in obs {
        if m.aborted.contains(id) {
            why.push(format!("ABORTED append {} is visible", tname(*id)));
        } else if let Some(seq) = m.seq_of.get(id) {
            if *seq > s {
                why.push(format!("sees {} committed at {seq} > snapshot {s} (decided-prefix rule)", tname(*id)));
            }
        } else {
            why.push(format!("unknown element {}", tname(*id)));
        }
    }
    for id in exp {
        if !obs.contains(id) {
            why.push(format!(
                "misses {} committed at {} <= snapshot {s}",
                tname(*id),
                m.seq_of[id]
            ));
        }
    }
    if !final_list.starts_with(obs) {
        why.push("not a prefix of the final list".to_string());
    }
    if why.is_empty() {
        why.push("order differs from commit-seq order".to_string());
    }
    why
}

/// Checks the history against the live Db, then reports.
fn check(r: &RunResult) -> Result<(), Vec<String>> {
    let cfg = &r.cfg;
    let mut out: Vec<String> = Vec::new();
    let m = build_model(cfg, &r.history, &mut out);

    // 1. Final lists: every committed append exactly once, in commit order,
    //    no aborted append anywhere.
    let mut finals: Vec<Vec<u32>> = Vec::with_capacity(cfg.keys);
    for k in 0..cfg.keys {
        let got = decode(r.db.get(&key_bytes(k)).expect("final read"));
        let exp: Vec<u32> = m.per_key[k].iter().map(|(_, id)| *id).collect();
        if got != exp {
            for (_, id) in &m.per_key[k] {
                match got.iter().filter(|x| *x == id).count() {
                    1 => {}
                    0 => out.push(format!("k{k:03}: committed append {} LOST from the final list", tname(*id))),
                    n => out.push(format!("k{k:03}: committed append {} appears {n} times", tname(*id))),
                }
            }
            for id in &got {
                if m.aborted.contains(id) {
                    out.push(format!("k{k:03}: ABORTED append {} in the final list", tname(*id)));
                } else if !m.seq_of.contains_key(id) {
                    out.push(format!("k{k:03}: unknown element {} in the final list", tname(*id)));
                }
            }
            out.push(format!(
                "k{k:03}: final list {} != commit-seq order {}",
                lname(&got),
                lname(&exp)
            ));
        }
        finals.push(got);
    }

    // 2. Reads: decided prefix, exactly. 3. Repeatable read.
    for t in &r.history {
        let mut seen: BTreeMap<usize, &Vec<u32>> = BTreeMap::new();
        for (k, obs) in &t.reads {
            let exp = list_at(&m.per_key[*k], t.snapshot);
            if *obs != exp {
                let why = explain_list(&m, t.snapshot, obs, &exp, &finals[*k]);
                out.push(format!(
                    "{} read k{k:03} at S={} as {} but the decided prefix is {}: {}",
                    tname(t.id),
                    t.snapshot,
                    lname(obs),
                    lname(&exp),
                    why.join("; ")
                ));
            }
            if let Some(first) = seen.insert(*k, obs) {
                if first != obs {
                    out.push(format!(
                        "{} read k{k:03} twice at S={}: {} then {} (repeatable read)",
                        tname(t.id),
                        t.snapshot,
                        lname(first),
                        lname(obs)
                    ));
                }
            }
        }
    }

    // 4. First-committer-wins: a committed writer of k saw every earlier
    //    committed writer of k.
    let snap_of: BTreeMap<u32, u64> = r.history.iter().map(|t| (t.id, t.snapshot)).collect();
    for k in 0..cfg.keys {
        for w in m.per_key[k].windows(2) {
            let (prev_seq, prev) = w[0];
            let (seq, id) = w[1];
            let s = snap_of[&id];
            if s < prev_seq {
                out.push(format!(
                    "LOST UPDATE on k{k:03}: {} (S={s}) committed at {seq} without seeing {} committed at {prev_seq}",
                    tname(id),
                    tname(prev)
                ));
            }
        }
    }

    // 5. Time travel: every recorded snapshot still reads as the model says,
    //    or is refused because collection passed it -- never answered wrong.
    let ct = r.db.collected_through();
    let snaps: Vec<u64> = m.snapshots.iter().copied().collect();
    let stride = (snaps.len() / 200).max(1);
    for &s in snaps.iter().step_by(stride) {
        for k in 0..cfg.keys {
            let exp = list_at(&m.per_key[k], s);
            let exp_seq = m.per_key[k].iter().take_while(|(q, _)| *q <= s).last().map(|(q, _)| *q);
            match (s < ct, r.db.get_at(&key_bytes(k), s)) {
                (true, Ok(v)) => {
                    if decode(v.clone()) != exp {
                        out.push(format!(
                            "time travel k{k:03}@{s} below collected_through {ct}: answered {} instead of refusing (model {})",
                            lname(&decode(v)),
                            lname(&exp)
                        ));
                    }
                }
                (true, Err(_)) => {}
                (false, Err(e)) => out.push(format!("time travel k{k:03}@{s} refused though {s} >= collected_through {ct}: {e}")),
                (false, Ok(v)) => {
                    let got = decode(v);
                    if got != exp {
                        out.push(format!(
                            "time travel k{k:03}@{s}: {} but the model says {}",
                            lname(&got),
                            lname(&exp)
                        ));
                    }
                    match r.db.get_stamped_at(&key_bytes(k), s).expect("stamped read") {
                        None if exp.is_empty() => {}
                        Some((_, stamp)) if Some(stamp) == exp_seq => {}
                        other => out.push(format!(
                            "time travel k{k:03}@{s}: version stamp {:?}, expected {exp_seq:?}",
                            other.map(|(_, q)| q)
                        )),
                    }
                }
            }
        }
    }

    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}

/// The final lists again through a fresh open of the same bucket, and the
/// same time-travel sample: what a restart would see.
fn check_reopened(r: &RunResult, re: &Db) -> Result<(), Vec<String>> {
    let cfg = &r.cfg;
    let mut out = Vec::new();
    let m = build_model(cfg, &r.history, &mut Vec::new());
    for k in 0..cfg.keys {
        let got = decode(re.get(&key_bytes(k)).expect("read after reopen"));
        let exp: Vec<u32> = m.per_key[k].iter().map(|(_, id)| *id).collect();
        if got != exp {
            out.push(format!(
                "REOPEN k{k:03}: final list {} != commit-seq order {}",
                lname(&got),
                lname(&exp)
            ));
            for id in &got {
                if m.aborted.contains(id) {
                    out.push(format!("REOPEN k{k:03}: ABORTED append {} applied", tname(*id)));
                }
            }
        }
    }
    let ct = re.collected_through();
    let snaps: Vec<u64> = m.snapshots.iter().copied().collect();
    let stride = (snaps.len() / 100).max(1);
    for &s in snaps.iter().step_by(stride) {
        for k in 0..cfg.keys {
            let exp = list_at(&m.per_key[k], s);
            match (s < ct, re.get_at(&key_bytes(k), s)) {
                (true, Ok(v)) if decode(v.clone()) != exp => out.push(format!(
                    "REOPEN time travel k{k:03}@{s} below collected_through {ct}: answered {} instead of refusing",
                    lname(&decode(v))
                )),
                (true, _) => {}
                (false, Err(e)) => out.push(format!("REOPEN time travel k{k:03}@{s} refused though {s} >= {ct}: {e}")),
                (false, Ok(v)) => {
                    let got = decode(v);
                    if got != exp {
                        out.push(format!(
                            "REOPEN time travel k{k:03}@{s}: {} but the model says {}",
                            lname(&got),
                            lname(&exp)
                        ));
                    }
                }
            }
        }
    }
    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}

/// Every transaction that touched `k`, oldest decision first.
fn excerpt(history: &[Txn], k: usize) -> String {
    let mut rows: Vec<(u64, &Txn)> = history
        .iter()
        .filter(|t| t.writes.contains(&k) || t.reads.iter().any(|(rk, _)| *rk == k))
        .map(|t| {
            let order = match t.fate {
                Fate::Committed { seq, .. }
                | Fate::AbortedAfterLanded { seq }
                | Fate::AbortedInFlight { seq } => seq,
                _ => t.snapshot,
            };
            (order, t)
        })
        .collect();
    rows.sort_by_key(|(o, t)| (*o, t.id));
    rows.iter().map(|(_, t)| format!("  {}", t.describe())).collect::<Vec<_>>().join("\n")
}

fn report(r: &RunResult, violations: &[String]) -> ! {
    eprintln!("\n==== ISOLATION VIOLATION: {} mode, seed {} ====", r.mode, r.cfg.seed);
    eprintln!("config: {:?}", r.cfg);
    let committed = r.history.iter().filter(|t| matches!(t.fate, Fate::Committed { .. })).count();
    eprintln!("{} txns, {committed} committed, {} folds", r.history.len(), r.folds);
    for v in violations.iter().take(40) {
        eprintln!("VIOLATION: {v}");
    }
    if violations.len() > 40 {
        eprintln!("... and {} more", violations.len() - 40);
    }
    let mut keys: BTreeSet<usize> = BTreeSet::new();
    for v in violations {
        if let Some(i) = v.find("k0") {
            if let Ok(k) = v[i + 1..i + 4].parse::<usize>() {
                keys.insert(k);
            }
        }
    }
    for k in keys.iter().take(3) {
        eprintln!("---- history of k{k:03} ----\n{}", excerpt(&r.history, *k));
    }
    panic!("{} mode, seed {}: {} isolation violation(s)", r.mode, r.cfg.seed, violations.len());
}

fn verify(r: RunResult) -> (usize, usize) {
    if let Err(v) = check(&r) {
        report(&r, &v);
    }
    let committed = r.history.iter().filter(|t| matches!(t.fate, Fate::Committed { .. })).count();
    let RunResult { cfg, mode, history, db, store, folds } = r;
    // Durability: what a restart sees. Dropping the writer releases its lease.
    drop(db);
    let re = Db::open(Arc::clone(&store)).expect("reopen");
    let again = RunResult {
        cfg,
        mode,
        history,
        db: re,
        store,
        folds,
    };
    // check_reopened reads through `again.db`, the reopened one.
    if let Err(v) = check_reopened(&again, &again.db) {
        report(&again, &v);
    }
    (again.history.len(), committed)
}

fn sweep(mode: &str, seeds: std::ops::RangeInclusive<u64>, txns_per_worker: usize) {
    let mut txns = 0;
    let mut committed = 0;
    for seed in seeds.clone() {
        let cfg = config(seed, txns_per_worker);
        let r = match mode {
            "threaded" => run_threaded(cfg),
            _ => run_scheduled(cfg),
        };
        let (t, c) = verify(r);
        txns += t;
        committed += c;
    }
    eprintln!("{mode}: {} seeds, {txns} txns, {committed} committed, no violations", seeds.count());
}

// ---------------------------------------------------------------------------
// Tests.

/// Real threads over one `Arc<Mutex<Db>>`, a writer thread that sometimes
/// holds a landed flight back, and a compactor thread. The workload is
/// deterministic per seed; the interleaving is the scheduler's.
#[test]
fn threaded_list_append_50_seeds() {
    sweep("threaded", 1..=50, 200);
}

/// The same transactions, writer and compactor interleaved by a seeded
/// scheduler on one thread: a failing seed reproduces exactly.
#[test]
fn scheduled_list_append_50_seeds() {
    sweep("scheduled", 1..=50, 200);
}

/// The oracle fires when validation is skipped: reads at S, writes
/// validated against nothing, so two appenders of one key both commit.
#[test]
fn oracle_catches_unvalidated_writes() {
    let mut cfg = config(1, 100);
    cfg.mutation = Mutation::ValidateAtLatest;
    let r = run_scheduled(cfg);
    let v = check(&r).expect_err("no first-committer-wins must be caught");
    assert!(v.iter().any(|s| s.contains("LOST UPDATE")), "{v:#?}");
    assert!(v.iter().any(|s| s.contains("LOST from the final list")), "{v:#?}");
}

/// The oracle fires on the bug the snapshot was redefined to fix: a
/// snapshot above the decided prefix. A number staged but not confirmed
/// sits below what the reader sees; when it confirms, its write was never
/// validated against, and the reader's append is lost.
#[test]
fn oracle_catches_a_snapshot_above_the_decided_prefix() {
    let mut fired = 0;
    for seed in 1..=20 {
        let mut cfg = config(seed, 100);
        cfg.mutation = Mutation::SnapshotAboveDecided;
        cfg.defer_pct = 60;
        cfg.async_pct = 0;
        let r = run_scheduled(cfg);
        if let Err(v) = check(&r) {
            assert!(
                v.iter().any(|s| s.contains("LOST UPDATE") || s.contains("misses")),
                "seed {seed}: {v:#?}"
            );
            fired += 1;
        }
    }
    assert!(fired > 0, "the mutation never surfaced in 20 seeds");
    eprintln!("snapshot-above-decided mutation caught in {fired}/20 seeds");
}

#[test]
#[ignore = "soak: 500 seeds in each mode; minutes in debug"]
fn soak_500_seeds() {
    sweep("scheduled", 1..=500, 200);
    sweep("threaded", 1..=500, 200);
}
