//! A fault-injecting [`Store`] wrapper for tests.
//!
//! Every fault this store can inject is something a real object store or the
//! network between us and it does: a PUT that lands but whose 200 never
//! comes back, a PUT that never leaves the building, a body that arrives
//! torn, a listing that has not caught up, a ranged GET that comes back
//! short. The engine's correctness argument is about what it does when the
//! store misbehaves in exactly these ways, and this is how a test says
//! "misbehave here, now".
//!
//! Deterministic: every random choice comes from an xorshift generator
//! seeded by the caller, so a failing seed replays. Faults come from two
//! sources, scripted [`Rule`]s (checked first) and a per-operation
//! probability. Every operation, with the fault injected into it if any,
//! goes into a log a test prints on failure.
//!
//! Delays are a hook, not a `thread::sleep`, because a sleep in production
//! code is what the determinism lint fences off; a threaded test installs
//! the sleeper it wants with [`FaultStore::set_sleeper`].

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::sync::Arc;

use pgsync::Mutex;

use crate::s3::{ObjectInfo, PutOutcome};
use crate::store::Store;

/// Which store method an operation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpKind {
    Put,
    Get,
    GetRange,
    List,
    Delete,
}

impl fmt::Display for OpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OpKind::Put => "put_if_absent",
            OpKind::Get => "get",
            OpKind::GetRange => "get_range",
            OpKind::List => "list",
            OpKind::Delete => "delete",
        })
    }
}

/// What can go wrong with one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The write is performed, then an error is returned: the response was
    /// lost. Applies to `put_if_absent` and `delete`.
    ErrAfterLanded,
    /// An error is returned and nothing is written. Applies to
    /// `put_if_absent` and `delete`.
    ErrBeforeLanded,
    /// The operation is delayed by this many milliseconds through the
    /// installed sleeper (a no-op by default), then performed normally.
    Delay(u64),
    /// The object is written truncated at a random point, or with a few
    /// bytes flipped, and `Ok(Written)` is returned. Applies to
    /// `put_if_absent`.
    TornObject,
    /// `put_if_absent` reports `AlreadyExists` without writing anything.
    PhantomExists,
    /// `list` omits the newest (lexicographically last) `n` objects.
    ListStale(u32),
    /// `get`, `get_range` or `list` fails with an error.
    GetErr,
    /// `get_range` returns fewer bytes than were asked for.
    GetRangeShort,
}

impl Fault {
    /// Whether this fault makes sense for the given operation.
    pub fn applies_to(self, op: OpKind) -> bool {
        match self {
            Fault::ErrAfterLanded | Fault::ErrBeforeLanded => matches!(op, OpKind::Put | OpKind::Delete),
            Fault::Delay(_) => true,
            Fault::TornObject | Fault::PhantomExists => op == OpKind::Put,
            Fault::ListStale(_) => op == OpKind::List,
            Fault::GetErr => matches!(op, OpKind::Get | OpKind::GetRange | OpKind::List),
            Fault::GetRangeShort => op == OpKind::GetRange,
        }
    }

    /// Every kind, with the parameters random faults use.
    pub fn all() -> Vec<Fault> {
        vec![
            Fault::ErrAfterLanded,
            Fault::ErrBeforeLanded,
            Fault::Delay(5),
            Fault::TornObject,
            Fault::PhantomExists,
            Fault::ListStale(1),
            Fault::GetErr,
            Fault::GetRangeShort,
        ]
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Delay(ms) => write!(f, "Delay({ms}ms)"),
            Fault::ListStale(n) => write!(f, "ListStale({n})"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// A scripted fault: the `nth` operation of kind `op` on a key under
/// `prefix` gets `fault`. With `nth` of `None` every matching operation
/// does, up to `times` of them.
#[derive(Debug, Clone)]
pub struct Rule {
    pub op: OpKind,
    pub prefix: String,
    pub nth: Option<u64>,
    pub fault: Fault,
    pub times: Option<u32>,
    seen: u64,
    fired: u32,
}

impl Rule {
    /// The `nth` (1-based) matching operation gets the fault, once.
    pub fn nth(op: OpKind, prefix: &str, nth: u64, fault: Fault) -> Rule {
        Rule { op, prefix: prefix.to_string(), nth: Some(nth), fault, times: Some(1), seen: 0, fired: 0 }
    }

    /// Every matching operation gets the fault.
    pub fn every(op: OpKind, prefix: &str, fault: Fault) -> Rule {
        Rule { op, prefix: prefix.to_string(), nth: None, fault, times: None, seen: 0, fired: 0 }
    }

    /// Every matching operation gets the fault, the first `times` of them.
    pub fn first(op: OpKind, prefix: &str, times: u32, fault: Fault) -> Rule {
        Rule { op, prefix: prefix.to_string(), nth: None, fault, times: Some(times), seen: 0, fired: 0 }
    }

    fn matches(&mut self, op: OpKind, key: &str) -> Option<Fault> {
        if op != self.op || !key.starts_with(&self.prefix) || !self.fault.applies_to(op) {
            return None;
        }
        if self.times.is_some_and(|t| self.fired >= t) {
            return None;
        }
        self.seen += 1;
        let hit = match self.nth {
            Some(n) => self.seen == n,
            None => true,
        };
        if hit {
            self.fired += 1;
            Some(self.fault)
        } else {
            None
        }
    }
}

/// One store operation as the log records it.
#[derive(Debug, Clone)]
pub struct Event {
    /// Position in the log, from 1.
    pub n: u64,
    pub op: OpKind,
    pub key: String,
    /// Bytes written, or the range asked for, or nothing.
    pub detail: String,
    pub fault: Option<Fault>,
    /// What the caller was told.
    pub result: String,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:<5} {} {}", self.n, self.op, self.key)?;
        if !self.detail.is_empty() {
            write!(f, " {}", self.detail)?;
        }
        if let Some(fault) = self.fault {
            write!(f, "  <<{fault}>>")?;
        }
        write!(f, "  -> {}", self.result)
    }
}

/// xorshift64*: small, seedable, good enough to pick faults with.
#[derive(Debug, Clone)]
pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> XorShift {
        // Zero is a fixed point; mix the seed so that seed 0 works too.
        XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03 | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Uniform in `[0, n)`; `0` when `n` is `0`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
    pub fn chance(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }
}

struct State {
    rng: XorShift,
    rules: Vec<Rule>,
    /// Probability that an operation with no scripted fault gets a random
    /// one, and which kinds it may be.
    rate: f64,
    kinds: Vec<Fault>,
    enabled: bool,
    log: Vec<Event>,
    /// Keys whose bodies were written torn, so a test knows a later
    /// decode failure is the store's doing.
    torn: BTreeSet<String>,
    faults_injected: u64,
}

type Sleeper = Box<dyn Fn(u64) + Send + Sync>;

/// A [`Store`] that injects faults into another. See the module doc.
pub struct FaultStore {
    inner: Arc<dyn Store>,
    state: Mutex<State>,
    sleeper: Mutex<Option<Sleeper>>,
}

impl FaultStore {
    /// Wraps `inner`; no faults until rules or a rate are set.
    pub fn new(inner: Arc<dyn Store>, seed: u64) -> FaultStore {
        FaultStore {
            inner,
            state: Mutex::new(State {
                rng: XorShift::new(seed),
                rules: Vec::new(),
                rate: 0.0,
                kinds: Fault::all(),
                enabled: true,
                log: Vec::new(),
                torn: BTreeSet::new(),
                faults_injected: 0,
            }),
            sleeper: Mutex::new(None),
        }
    }

    /// The store underneath, for a test that wants to look at the bucket
    /// without going through the faults.
    pub fn inner(&self) -> &Arc<dyn Store> {
        &self.inner
    }

    pub fn add_rule(&self, rule: Rule) {
        self.state.lock().unwrap().rules.push(rule);
    }

    pub fn clear_rules(&self) {
        self.state.lock().unwrap().rules.clear();
    }

    /// Probability, per operation, of a random fault of one of `kinds`
    /// (those that apply to the operation). `kinds` empty means all.
    pub fn set_random(&self, rate: f64, kinds: &[Fault]) {
        let mut s = self.state.lock().unwrap();
        s.rate = rate;
        s.kinds = if kinds.is_empty() { Fault::all() } else { kinds.to_vec() };
    }

    /// Turns injection off (or on) without forgetting the rules: how a test
    /// verifies against the bucket as it truly is.
    pub fn set_enabled(&self, on: bool) {
        self.state.lock().unwrap().enabled = on;
    }

    /// What `Fault::Delay` calls. A threaded test installs a real sleep.
    pub fn set_sleeper(&self, f: impl Fn(u64) + Send + Sync + 'static) {
        *self.sleeper.lock().unwrap() = Some(Box::new(f));
    }

    pub fn events(&self) -> Vec<Event> {
        self.state.lock().unwrap().log.clone()
    }

    pub fn clear_log(&self) {
        self.state.lock().unwrap().log.clear();
    }

    /// The whole log, one operation per line.
    pub fn log(&self) -> String {
        let s = self.state.lock().unwrap();
        let mut out = String::new();
        for e in &s.log {
            out.push_str(&e.to_string());
            out.push('\n');
        }
        out
    }

    /// The last `n` lines of the log: what a failure message wants.
    pub fn tail(&self, n: usize) -> String {
        let s = self.state.lock().unwrap();
        let skip = s.log.len().saturating_sub(n);
        let mut out = String::new();
        if skip > 0 {
            out.push_str(&format!("... {skip} earlier operation(s) omitted ...\n"));
        }
        for e in &s.log[skip..] {
            out.push_str(&e.to_string());
            out.push('\n');
        }
        out
    }

    /// Only the operations that had a fault injected.
    pub fn faults(&self) -> Vec<Event> {
        self.state.lock().unwrap().log.iter().filter(|e| e.fault.is_some()).cloned().collect()
    }

    pub fn faults_injected(&self) -> u64 {
        self.state.lock().unwrap().faults_injected
    }

    /// Keys written torn so far.
    pub fn torn_keys(&self) -> Vec<String> {
        self.state.lock().unwrap().torn.iter().cloned().collect()
    }

    /// Tears `body` with the generator: truncates it or flips bytes.
    pub fn tear(rng: &mut XorShift, body: &[u8]) -> Vec<u8> {
        if body.is_empty() {
            return Vec::new();
        }
        if rng.chance(0.5) {
            let at = rng.below(body.len() as u64) as usize;
            body[..at].to_vec()
        } else {
            let mut b = body.to_vec();
            let flips = 1 + rng.below(3) as usize;
            for _ in 0..flips {
                let i = rng.below(b.len() as u64) as usize;
                let bit = 1u8 << rng.below(8);
                b[i] ^= bit;
            }
            b
        }
    }

    /// Decides the fault for one operation, if any, and reserves its log
    /// slot. The slot is filled by `record`.
    fn plan(&self, op: OpKind, key: &str, detail: String) -> (u64, Option<Fault>) {
        let mut s = self.state.lock().unwrap();
        let n = s.log.len() as u64 + 1;
        s.log.push(Event { n, op, key: key.to_string(), detail, fault: None, result: String::new() });
        if !s.enabled {
            return (n, None);
        }
        let mut fault = s.rules.iter_mut().find_map(|r| r.matches(op, key));
        let rate = s.rate;
        if fault.is_none() && rate > 0.0 && s.rng.chance(rate) {
            let applicable: Vec<Fault> = s.kinds.iter().copied().filter(|f| f.applies_to(op)).collect();
            if !applicable.is_empty() {
                let i = s.rng.below(applicable.len() as u64) as usize;
                fault = Some(applicable[i]);
            }
        }
        if fault.is_some() {
            s.faults_injected += 1;
        }
        let idx = (n - 1) as usize;
        s.log[idx].fault = fault;
        (n, fault)
    }

    fn record(&self, n: u64, result: String) {
        let mut s = self.state.lock().unwrap();
        let idx = (n - 1) as usize;
        if let Some(e) = s.log.get_mut(idx) {
            e.result = result;
        }
    }

    fn injected(&self, n: u64, fault: Fault, op: OpKind, key: &str) -> io::Error {
        io::Error::other(format!("injected fault #{n}: {fault} on {op} {key}"))
    }

    fn delay(&self, ms: u64) {
        if let Some(f) = self.sleeper.lock().unwrap().as_ref() {
            f(ms.min(1_000));
        }
    }

    fn rng<T>(&self, f: impl FnOnce(&mut XorShift) -> T) -> T {
        f(&mut self.state.lock().unwrap().rng)
    }
}

fn show_put(r: &io::Result<PutOutcome>) -> String {
    match r {
        Ok(PutOutcome::Written) => "Written".into(),
        Ok(PutOutcome::AlreadyExists) => "AlreadyExists".into(),
        Err(e) => format!("Err({e})"),
    }
}

fn show_bytes(r: &io::Result<Option<Vec<u8>>>) -> String {
    match r {
        Ok(Some(b)) => format!("Some({} bytes)", b.len()),
        Ok(None) => "None".into(),
        Err(e) => format!("Err({e})"),
    }
}

impl Store for FaultStore {
    fn put_if_absent(&self, key: &str, body: &[u8]) -> io::Result<PutOutcome> {
        let (n, fault) = self.plan(OpKind::Put, key, format!("({} bytes)", body.len()));
        let r = match fault {
            None => self.inner.put_if_absent(key, body),
            Some(Fault::Delay(ms)) => {
                self.delay(ms);
                self.inner.put_if_absent(key, body)
            }
            Some(f @ Fault::ErrAfterLanded) => {
                let _ = self.inner.put_if_absent(key, body);
                Err(self.injected(n, f, OpKind::Put, key))
            }
            Some(f @ Fault::ErrBeforeLanded) => Err(self.injected(n, f, OpKind::Put, key)),
            Some(Fault::TornObject) => {
                let torn = self.rng(|rng| FaultStore::tear(rng, body));
                let r = self.inner.put_if_absent(key, &torn);
                if matches!(r, Ok(PutOutcome::Written)) {
                    self.state.lock().unwrap().torn.insert(key.to_string());
                }
                r
            }
            Some(Fault::PhantomExists) => Ok(PutOutcome::AlreadyExists),
            Some(f) => Err(self.injected(n, f, OpKind::Put, key)),
        };
        self.record(n, show_put(&r));
        r
    }

    fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let (n, fault) = self.plan(OpKind::Get, key, String::new());
        let r = match fault {
            None => self.inner.get(key),
            Some(Fault::Delay(ms)) => {
                self.delay(ms);
                self.inner.get(key)
            }
            Some(f) => Err(self.injected(n, f, OpKind::Get, key)),
        };
        self.record(n, show_bytes(&r));
        r
    }

    fn get_range(&self, key: &str, offset: u64, len: u64) -> io::Result<Option<Vec<u8>>> {
        let (n, fault) = self.plan(OpKind::GetRange, key, format!("[{offset}..+{len}]"));
        let r = match fault {
            None => self.inner.get_range(key, offset, len),
            Some(Fault::Delay(ms)) => {
                self.delay(ms);
                self.inner.get_range(key, offset, len)
            }
            Some(Fault::GetRangeShort) => match self.inner.get_range(key, offset, len) {
                Ok(Some(b)) if !b.is_empty() => {
                    let keep = self.rng(|rng| rng.below(b.len() as u64)) as usize;
                    Ok(Some(b[..keep].to_vec()))
                }
                other => other,
            },
            Some(f) => Err(self.injected(n, f, OpKind::GetRange, key)),
        };
        self.record(n, show_bytes(&r));
        r
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<ObjectInfo>> {
        let (n, fault) = self.plan(OpKind::List, prefix, String::new());
        let r = match fault {
            None => self.inner.list(prefix),
            Some(Fault::Delay(ms)) => {
                self.delay(ms);
                self.inner.list(prefix)
            }
            Some(Fault::ListStale(k)) => self.inner.list(prefix).map(|mut v| {
                v.sort_by(|a, b| a.key.cmp(&b.key));
                let keep = v.len().saturating_sub(k as usize);
                v.truncate(keep);
                v
            }),
            Some(f) => Err(self.injected(n, f, OpKind::List, prefix)),
        };
        self.record(
            n,
            match &r {
                Ok(v) => format!("{} object(s)", v.len()),
                Err(e) => format!("Err({e})"),
            },
        );
        r
    }

    fn delete(&self, key: &str) -> io::Result<()> {
        let (n, fault) = self.plan(OpKind::Delete, key, String::new());
        let r = match fault {
            None => self.inner.delete(key),
            Some(Fault::Delay(ms)) => {
                self.delay(ms);
                self.inner.delete(key)
            }
            Some(f @ Fault::ErrAfterLanded) => {
                let _ = self.inner.delete(key);
                Err(self.injected(n, f, OpKind::Delete, key))
            }
            Some(f) => Err(self.injected(n, f, OpKind::Delete, key)),
        };
        self.record(
            n,
            match &r {
                Ok(()) => "Ok".into(),
                Err(e) => format!("Err({e})"),
            },
        );
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

    fn wrapped(seed: u64) -> (Arc<MemStore>, Arc<FaultStore>) {
        let m = Arc::new(MemStore::new());
        let f = Arc::new(FaultStore::new(Arc::clone(&m) as Arc<dyn Store>, seed));
        (m, f)
    }

    #[test]
    fn a_scripted_rule_hits_the_nth_matching_operation_only() {
        let (m, f) = wrapped(1);
        f.add_rule(Rule::nth(OpKind::Put, "commit/", 2, Fault::ErrAfterLanded));
        assert_eq!(f.put_if_absent("commit/1", b"a").unwrap(), PutOutcome::Written);
        assert_eq!(f.put_if_absent("other/1", b"x").unwrap(), PutOutcome::Written);
        assert!(f.put_if_absent("commit/2", b"b").is_err(), "the second commit/ put");
        assert_eq!(m.get("commit/2").unwrap(), Some(b"b".to_vec()), "but it landed");
        assert_eq!(f.put_if_absent("commit/3", b"c").unwrap(), PutOutcome::Written, "once only");
        assert_eq!(f.faults().len(), 1);
        assert!(f.log().contains("<<ErrAfterLanded>>"), "{}", f.log());
    }

    #[test]
    fn phantom_exists_and_err_before_landed_write_nothing() {
        let (m, f) = wrapped(2);
        f.add_rule(Rule::nth(OpKind::Put, "a", 1, Fault::PhantomExists));
        f.add_rule(Rule::nth(OpKind::Put, "b", 1, Fault::ErrBeforeLanded));
        assert_eq!(f.put_if_absent("a", b"1").unwrap(), PutOutcome::AlreadyExists);
        assert!(f.put_if_absent("b", b"2").is_err());
        assert!(m.list("").unwrap().is_empty());
    }

    #[test]
    fn a_torn_object_differs_from_what_was_sent_and_is_remembered() {
        for seed in 0..50 {
            let (m, f) = wrapped(seed);
            f.add_rule(Rule::every(OpKind::Put, "run/", Fault::TornObject));
            let body: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
            assert_eq!(f.put_if_absent("run/1", &body).unwrap(), PutOutcome::Written);
            let stored = m.get("run/1").unwrap().unwrap();
            assert_ne!(stored, body, "seed {seed}");
            assert_eq!(f.torn_keys(), vec!["run/1".to_string()]);
        }
    }

    #[test]
    fn a_stale_list_omits_the_newest_and_a_short_range_comes_back_short() {
        let (_, f) = wrapped(3);
        for k in ["x/1", "x/2", "x/3"] {
            f.put_if_absent(k, b"0123456789").unwrap();
        }
        f.add_rule(Rule::nth(OpKind::List, "x/", 1, Fault::ListStale(1)));
        let keys: Vec<String> = f.list("x/").unwrap().into_iter().map(|i| i.key).collect();
        assert_eq!(keys, vec!["x/1", "x/2"]);
        f.add_rule(Rule::every(OpKind::GetRange, "x/", Fault::GetRangeShort));
        let b = f.get_range("x/1", 0, 10).unwrap().unwrap();
        assert!(b.len() < 10, "{}", b.len());
        f.add_rule(Rule::every(OpKind::Get, "x/", Fault::GetErr));
        assert!(f.get("x/1").is_err());
    }

    #[test]
    fn the_same_seed_gives_the_same_faults_and_disabling_gives_none() {
        let run = |seed: u64| -> Vec<Option<Fault>> {
            let (_, f) = wrapped(seed);
            f.set_random(0.5, &[]);
            for i in 0..40 {
                let _ = f.put_if_absent(&format!("k/{i}"), b"v");
                let _ = f.get(&format!("k/{i}"));
                let _ = f.list("k/");
            }
            f.events().into_iter().map(|e| e.fault).collect()
        };
        assert_eq!(run(7), run(7));
        assert_ne!(run(7), run(8));
        assert!(run(7).iter().any(Option::is_some));

        let (_, f) = wrapped(7);
        f.set_random(1.0, &[]);
        f.set_enabled(false);
        for i in 0..10 {
            f.put_if_absent(&format!("k/{i}"), b"v").unwrap();
        }
        assert_eq!(f.faults_injected(), 0);
    }

    #[test]
    fn a_delay_goes_through_the_installed_sleeper() {
        let (_, f) = wrapped(4);
        let slept = Arc::new(Mutex::new(Vec::new()));
        let s2 = Arc::clone(&slept);
        f.set_sleeper(move |ms| s2.lock().unwrap().push(ms));
        f.add_rule(Rule::every(OpKind::Get, "", Fault::Delay(7)));
        f.get("anything").unwrap();
        assert_eq!(*slept.lock().unwrap(), vec![7]);
    }
}
