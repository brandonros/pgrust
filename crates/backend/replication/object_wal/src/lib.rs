//! Native object-backed startup and WAL publication. Ordinary startup is unchanged.
//! Replacement requires an operator's exact-head assertion after old compute stops.
#![cfg(unix)]

mod archive;
mod create;
mod decode;
mod http;
mod image;
mod renewal;
use archive::num;
use pgsync::Mutex;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU64,
    Ordering::{Acquire, Release},
};
use types_error::{FATAL, PANIC, PgError, PgResult};
use types_storage::waiteventset::{WL_LATCH_SET, WL_POSTMASTER_DEATH, WL_TIMEOUT};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn digest(bytes: &[u8]) -> String {
    pg_sha2::sha256(bytes)
        .iter()
        .map(|n| format!("{n:02x}"))
        .collect()
}
fn fresh() -> Result<String> {
    let mut b = [0; 16];
    if !pg_strong_random::pg_strong_random(&mut b) {
        return Err("random generation failed".into());
    }
    Ok(b.iter().map(|n| format!("{n:02x}")).collect())
}
fn lsn(s: &str) -> Result<u64> {
    let (a, b) = s.split_once('/').ok_or("invalid LSN")?;
    Ok((u32::from_str_radix(a, 16)? as u64) << 32 | u32::from_str_radix(b, 16)? as u64)
}
fn lsn_text(n: u64) -> String {
    format!("{:X}/{:X}", n >> 32, n as u32)
}
fn pg_error(e: impl std::fmt::Display) -> Box<PgError> {
    Box::new(PgError::new(FATAL, format!("object WAL: {e}")))
}
struct Runtime {
    store: http::Store,
    input: Input,
    _lock: Option<File>,
}
enum Input {
    Restore(archive::Restored),
    Create(PathBuf),
}
static RUNTIME: Mutex<Option<Runtime>> = Mutex::new(None);
static RECOVERED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static STARTUP_END: AtomicU64 = AtomicU64::new(0);
static WORKER: AtomicI32 = AtomicI32::new(-1);
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn setting(value: Option<String>, name: &str) -> Result<String> {
    value
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{name} is required").into())
}

pub fn prepare() -> PgResult<()> {
    if !guc_tables::backing::pgrust_s3() {
        if guc_tables::backing::pgrust_s3_create() {
            return Err(pg_error("s3_create requires pgrust.s3"));
        }
        return Ok(());
    }
    #[cfg(pgrust_sim)]
    return Err(pg_error(
        "native S3 transport and restore are unavailable under simulated I/O",
    ));
    #[cfg(not(pgrust_sim))]
    prepare_inner().map_err(pg_error)
}
fn prepare_inner() -> Result<()> {
    use guc_tables::backing as g;
    if !g::pgrust_strict_synchronous_commit()
        || g::pgrust_memory_wal_mb() <= 0
        || g::restart_after_crash()
        || guc_tables::vars::EnableHotStandby.read()
        || guc_tables::vars::XLogArchiveMode.read() != 0
        || guc_tables::vars::wal_level.read() != transam_xlog::WAL_LEVEL_REPLICA
    {
        return Err("S3 requires strict completion, memory WAL, replica WAL, restart_after_crash=off, hot_standby=off, archive_mode=off".into());
    }
    guc::strict_sync::configure()?;
    guc::SetConfigOption(
        "summarize_wal",
        Some("on"),
        types_guc::PGC_POSTMASTER,
        types_guc::PGC_S_OVERRIDE,
    )?;
    let store = http::Store::new(
        &setting(g::pgrust_s3_endpoint(), "pgrust.s3_endpoint")?,
        setting(g::pgrust_s3_bucket(), "pgrust.s3_bucket")?,
        g::pgrust_s3_region()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "us-east-1".into()),
        setting(g::pgrust_s3_prefix(), "pgrust.s3_prefix")?,
    )?;
    if g::pgrust_s3_create() {
        if g::pgrust_s3_fenced_head().is_some_and(|v| !v.is_empty()) {
            return Err("creation must not supply a replacement authorization".into());
        }
        if store.get("head")?.is_some() {
            return Err("S3 archive already exists".into());
        }
        // Without a head there is no fenced recovery state to authorize a
        // sweep. Refuse repeated partial creations instead of leaking another
        // baseline or deleting objects belonging to a concurrent creator.
        let mut after = None;
        loop {
            let keys = store.list_after(after.as_deref())?;
            if keys.iter().any(|key| http::owned_key(key)) {
                return Err("archive prefix contains an incomplete creation; use an unused prefix or clear it after stopping all previous creators".into());
            }
            if keys.is_empty() {
                break;
            }
            after = keys.last().cloned();
        }
        let data = PathBuf::from(init_small::globals::DataDir().ok_or("missing data_directory")?);
        *pgsync::lock(&RUNTIME) = Some(Runtime {
            store,
            input: Input::Create(data),
            _lock: None,
        });
        syncrep_seams::wake_object_publisher::set(wake);
        return Ok(());
    }
    let expected = setting(g::pgrust_s3_fenced_head(), "pgrust.s3_fenced_head")?;
    if !http::address(&expected) {
        return Err("fenced head must be SHA256 observed after stopping previous compute".into());
    }
    let snapshot = store.required("head")?;
    if digest(&snapshot.body) != expected {
        return Err("bucket head differs from the explicitly fenced parent".into());
    }
    let data = PathBuf::from(init_small::globals::DataDir().ok_or("missing data_directory")?);
    let parent = data
        .parent()
        .ok_or("data_directory requires a parent")?
        .canonicalize()?;
    let name = data
        .file_name()
        .ok_or("invalid data_directory")?
        .to_str()
        .ok_or("non UTF-8 data_directory")?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent.join(format!(".{name}.object-wal.lock")))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another launch owns this local destination".into());
    }
    if fs::symlink_metadata(&data).is_ok() {
        return Err("S3 startup requires a new data_directory; existing local state is not a recovery source".into());
    }
    let stage = Stage(parent.join(format!(".{name}.restore-{}", fresh()?)));
    fs::create_dir(&stage.0)?;
    fs::set_permissions(&stage.0, fs::Permissions::from_mode(0o700))?;
    let limit = g::pgrust_memory_wal_mb() as usize * 1024 * 1024;
    let mut restored = archive::restore(&store, snapshot, &stage.0, limit)?;
    if restored.segment > limit / 8 {
        return Err("S3 renewal requires memory WAL capacity for at least eight segments".into());
    }
    if store.required("head")? != restored.snapshot {
        return Err("bucket changed during restore".into());
    }
    (restored.snapshot, restored.head) =
        renewal::reclaim_abandoned(&store, &restored.snapshot, &restored.head)?;
    // Restored configuration is data, not authority for this new run. Configuration
    // comes from the external config directory selected before materialization.
    fs::write(restored.data.join("postgresql.auto.conf"), b"")?;
    fs::write(restored.data.join("recovery.signal"), b"")?;
    let values = [
        ("restore_command", String::new()),
        (
            "recovery_target_lsn",
            lsn_text(num(&restored.head, "record_start")?),
        ),
        (
            "recovery_target_timeline",
            num(&restored.head, "timeline")?.to_string(),
        ),
        ("recovery_target_inclusive", "true".into()),
        ("recovery_target_action", "promote".into()),
        ("recovery_target", String::new()),
        ("recovery_target_name", String::new()),
        ("recovery_target_time", String::new()),
        ("recovery_target_xid", String::new()),
    ];
    for (name, value) in values {
        guc::SetConfigOption(
            name,
            Some(&value),
            types_guc::PGC_POSTMASTER,
            types_guc::PGC_S_OVERRIDE,
        )?;
    }
    // Native recovery needs table/index files locally, but no WAL segment files.
    fs::set_permissions(&restored.data, fs::Permissions::from_mode(0o700))?;
    fs::rename(&restored.data, &data)?;
    restored.data = data;
    xlogutils::memory_wal::initialize(
        std::mem::take(&mut restored.segments),
        limit,
        restored.segment,
    )?;
    let mut runtime = pgsync::lock(&RUNTIME);
    if runtime.is_some() {
        return Err("duplicate native object startup".into());
    }
    *runtime = Some(Runtime {
        store,
        input: Input::Restore(restored),
        _lock: Some(lock),
    });
    syncrep_seams::wake_object_publisher::set(wake);
    Ok(())
}
/// Called only after the ordinary postmaster data-directory lock is held.
pub fn prepare_creation() -> PgResult<()> {
    if !guc_tables::backing::pgrust_s3_create() {
        return Ok(());
    }
    let guard = pgsync::lock(&RUNTIME);
    let Some(Runtime {
        input: Input::Create(data),
        ..
    }) = guard.as_ref()
    else {
        return Err(pg_error("missing creation state"));
    };
    create::seed(
        data,
        guc_tables::backing::pgrust_memory_wal_mb() as usize * 1024 * 1024,
    )
    .map_err(pg_error)
}

pub fn register_worker() -> PgResult<()> {
    if !guc_tables::backing::pgrust_s3() {
        return Ok(());
    }
    for (name, argument) in [("object WAL publisher", 0), ("object snapshot renewal", 1)] {
        bgworker::RegisterBackgroundWorker(&bgworker::BackgroundWorker {
            bgw_name: name.into(),
            bgw_type: name.into(),
            bgw_flags: bgworker::BGWORKER_SHMEM_ACCESS,
            bgw_start_time: bgworker::BgWorkerStartTime::PostmasterStart,
            bgw_restart_time: bgworker::BGW_NEVER_RESTART,
            bgw_main: worker,
            bgw_main_arg: argument,
            bgw_extra: [0; bgworker::BGW_EXTRALEN],
            bgw_notify_pid: 0,
        });
    }
    Ok(())
}
fn wake() {
    let proc = WORKER.load(Acquire);
    if proc >= 0 {
        latch::SetLatch(types_storage::latch::LatchHandle::proc(proc));
    }
}
fn wait(ms: i64) -> PgResult<()> {
    let rc = latch::WaitLatch(
        init_small::globals::MyLatch(),
        WL_LATCH_SET | WL_POSTMASTER_DEATH | WL_TIMEOUT,
        ms,
        0x0800_0000 | 52,
    )?;
    if rc & WL_POSTMASTER_DEATH != 0 {
        return Err(pg_error("postmaster died"));
    }
    Ok(())
}
pub fn finish_startup(interrupts: fn() -> PgResult<()>) -> PgResult<()> {
    if !guc_tables::backing::pgrust_s3() {
        return Ok(());
    }
    let end = transam_xlog::GetXLogInsertRecPtr();
    transam_xlog::XLogFlush(end)?;
    STARTUP_END.store(end, Release);
    RECOVERED.store(true, Release);
    wake();
    let deadline = pg_clock::mono_ms() + 90000;
    while !READY.load(Acquire) {
        interrupts()?;
        if pg_clock::mono_ms() > deadline {
            return Err(pg_error(
                "publisher did not authorize recovered startup within 90 seconds",
            ));
        }
        latch::ResetLatch(
            init_small::globals::MyLatch().ok_or_else(|| pg_error("startup has no latch"))?,
        );
        wait(100)?;
    }
    Ok(())
}
fn worker(argument: u64) -> PgResult<()> {
    let name = if argument == 0 {
        "object WAL publisher"
    } else {
        "object snapshot renewal"
    };
    let result = if argument == 0 {
        run_publisher()
    } else {
        renewal::run()
    };
    let reason = result
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "worker exited unexpectedly".into());
    // Commit waiters must not be released after loss of publication authority.
    elog::ereport(PANIC)
        .errmsg(format!("{name} stopped"))
        .errdetail(reason)
        .finish(types_error::ErrorLocation::new(
            file!(),
            line!() as i32,
            "object_wal::worker",
        ))
}
fn run_publisher() -> Result<()> {
    WORKER.store(init_small::globals::MyProcNumber(), Release);
    while !RECOVERED.load(Acquire) {
        postgres_seams::check_for_interrupts::call()?;
        wait(100)?;
    }
    let Runtime {
        store,
        input,
        _lock,
    } = pgsync::lock(&RUNTIME)
        .take()
        .ok_or("missing object state")?;
    let creating = matches!(&input, Input::Create(_));
    let mut restored = match input {
        Input::Restore(restored) => restored,
        Input::Create(data) => create::publish(&store, data)?,
    };
    let mut tli = 0;
    let flush = transam_xlog::GetFlushRecPtr(Some(&mut tli));
    if transam_xlog::GetSystemIdentifier() != restored.system || flush < num(&restored.head, "end")?
    {
        return Err("native recovery identity/bounds mismatch".into());
    }
    let (mut snapshot, mut head) = if creating {
        let end = num(&restored.head, "end")?;
        if end < STARTUP_END.load(Acquire) {
            return Err("initial archive precedes startup WAL".into());
        }
        syncrep_seams::confirm_object_flush::call(end)?;
        READY.store(true, Release);
        (restored.snapshot.clone(), restored.head.clone())
    } else {
        let history = fs::read(restored.data.join(format!("pg_wal/{tli:08X}.history")))?;
        archive::fork(
            &store,
            &restored.snapshot,
            &restored.head,
            tli,
            &history,
            &restored.root_history,
        )?
    };
    let mut last_checked = pg_clock::mono_ms();
    let mut renewing = true;
    let mut published_since_export = std::collections::BTreeSet::new();
    renewal::submit(renewal::Job::Cleanup {
        store: store.clone(),
        head: head.clone(),
    });
    let threshold = (guc_tables::backing::pgrust_memory_wal_mb() as u64 * 1024 * 1024 / 4)
        .max(4 * restored.segment as u64);

    loop {
        postgres_seams::check_for_interrupts::call()?;
        latch::ResetLatch(init_small::globals::MyLatch().ok_or("publisher has no latch")?);
        if let Some(done) = renewal::completed_at(num(&head, "end")?) {
            match done {
                renewal::Done::Export(prepared) => {
                    let (selected, next, chunks) = renewal::select(
                        &store,
                        &snapshot,
                        &head,
                        prepared,
                        std::mem::take(&mut published_since_export),
                        restored.segment,
                        restored.system,
                        &restored.data,
                    )?;
                    snapshot = selected;
                    head = next;
                    restored.chunks = chunks;
                    restored.root_history =
                        archive::eligibility(&store, &head, &archive::heads(&head)?)?.1;
                    last_checked = pg_clock::mono_ms();
                    renewal::submit(renewal::Job::Cleanup {
                        store: store.clone(),
                        head: head.clone(),
                    });
                }
                renewal::Done::Cleanup => renewing = false,
            }
        }
        let start = num(&head, "end")?;
        if !renewing
            && (start.saturating_sub(num(&head, "start")?) >= threshold
                || restored.chunks >= archive::MAX_CHUNKS / 2)
        {
            renewing = true;
            published_since_export.clear();
            renewal::submit(renewal::Job::Export {
                store: store.clone(),
                head: head.clone(),
            });
        }
        let mut current_tli = 0;
        let available = transam_xlog::GetFlushRecPtr(Some(&mut current_tli));
        if current_tli != tli || available < start {
            return Err("publisher WAL position changed unexpectedly".into());
        }
        if available > start {
            if restored.chunks >= archive::MAX_CHUNKS {
                return Err("WAL history capacity exhausted".into());
            }
            let base = start - start % restored.segment as u64;
            let end = available.min(start + 64 * 1024 * 1024);
            let mut bytes = vec![0; (end - base) as usize];
            if !xlogutils::memory_wal::read(tli, base, &mut bytes) {
                return Err("publisher missing retained WAL".into());
            }
            let (record, complete) = decode::last_record(
                &bytes,
                base,
                end,
                start,
                restored.system,
                tli,
                restored.segment,
            )?;
            if complete <= start && end < available {
                return Err("WAL record exceeds bounded publication batch".into());
            }
            // Background flushing can stop inside a record. Keep the durable
            // frontier unchanged until the complete record becomes readable.
            if complete > start {
                let payload = &bytes[(start - base) as usize..(complete - base) as usize];
                (snapshot, head) = archive::publish(&store, &snapshot, &head, payload, record)?;
                published_since_export.insert(format!("chunks/{}", digest(payload)));
                published_since_export
                    .insert(format!("descriptors/{}", archive::text(&head, "tail")?));
                restored.chunks += 1;
                syncrep_seams::confirm_object_flush::call(complete)?;
                if complete >= STARTUP_END.load(Acquire) {
                    READY.store(true, Release);
                }
                last_checked = pg_clock::mono_ms();
                continue;
            }
        }
        if pg_clock::mono_ms() - last_checked >= 1000 {
            if store.required("head")? != snapshot {
                return Err("publisher lost bucket ownership".into());
            }
            last_checked = pg_clock::mono_ms();
        }
        wait(1000)?;
    }
}
