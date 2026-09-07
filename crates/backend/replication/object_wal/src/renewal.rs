use crate::{
    Result,
    archive::{self, num, text},
    create, decode, digest, fresh,
    http::{Object, Store},
    image::Image,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs};

pub struct Prepared {
    image: String,
    old_objects: BTreeSet<String>,
    new_objects: BTreeSet<String>,
    manifest: String,
    start: u64,
    end: u64,
    timeline: u32,
}
pub enum Job {
    Export { store: Store, head: Value },
    Cleanup { store: Store, head: Value },
}
pub enum Done {
    Export(Prepared),
    Cleanup,
}
static REQUEST: pgsync::Mutex<Option<Job>> = pgsync::Mutex::new(None);
static RESPONSE: pgsync::Mutex<Option<Done>> = pgsync::Mutex::new(None);
pub fn submit(job: Job) {
    *pgsync::lock(&REQUEST) = Some(job);
}
pub fn completed_at(published: u64) -> Option<Done> {
    let mut result = pgsync::lock(&RESPONSE);
    if matches!(result.as_ref(), Some(Done::Export(p)) if p.end > published) {
        return None;
    }
    result.take()
}

pub fn run() -> Result<()> {
    loop {
        latch::ResetLatch(init_small::globals::MyLatch().ok_or("snapshot worker has no latch")?);
        postgres_seams::check_for_interrupts::call()?;
        let job = pgsync::lock(&REQUEST).take();
        if let Some(job) = job {
            let done = match job {
                Job::Export { store, head } => Done::Export(export(&store, &head)?),
                Job::Cleanup { store, head } => {
                    cleanup(&store, &head)?;
                    // Recompute native retention now, after the archive floor moved.
                    if !head["garbage"].is_null() {
                        checkpointer_seams::request_checkpoint::call(
                            transam_xlog::CHECKPOINT_FORCE | transam_xlog::CHECKPOINT_WAIT,
                        )?;
                    }
                    Done::Cleanup
                }
            };
            *pgsync::lock(&RESPONSE) = Some(done);
            crate::wake();
        }
        crate::wait(100)?;
    }
}
fn info(store: &Store, head: &Value) -> Result<Value> {
    archive::eligibility(store, head, &archive::heads(head)?).map(|(i, _)| i)
}
fn export(store: &Store, head: &Value) -> Result<Prepared> {
    let old_objects = objects(store, head)?;
    let old = info(store, head)?;
    let parent = Image::load(store, text(&old, "image")?)?;
    let manifest = parent.manifest();
    let capture = create::capture(Some(&manifest))?;
    // Only immutable payload/index uploads get the longer retry allowance.
    // Capture and selection are not restarted, and WAL keeps its own worker.
    let uploads = store.clone().retry_snapshot_uploads();
    let image = crate::image::export(&uploads, &capture, Some(&parent))?;
    Ok(Prepared {
        old_objects,
        new_objects: image.objects(),
        image: image.save(&uploads)?,
        manifest: digest(&image.manifest()),
        start: capture.start,
        end: capture.end,
        timeline: capture.timeline,
    })
}

/// Objects required by this selected recovery state, including native timeline
/// history and the retirement journal itself.
fn objects(store: &Store, head: &Value) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    let mut tail = head["tail"].clone();
    let mut count = 0;
    while let Some(key) = tail.as_str() {
        count += 1;
        if count > archive::MAX_CHUNKS {
            return Err("retirement WAL inventory limit".into());
        }
        let d = archive::parse(&store.verified("descriptors", key)?)?;
        result.insert(format!("descriptors/{key}"));
        result.insert(format!("chunks/{}", text(&d, "chunk")?));
        tail = d["previous"].clone();
    }
    for node in archive::heads(head)? {
        if let Some(key) = node["transition"]["history"].as_str() {
            result.insert(format!("histories/{key}"));
        }
    }
    let backup = info(store, head)?;
    if let Some(key) = backup["root_history"].as_str() {
        result.insert(format!("histories/{key}"));
    }
    if let Some(key) = head["backup"].as_str() {
        result.insert(format!("backups/{key}"));
    }
    let key = text(&backup, "image")?;
    result.insert(format!("snapshot-index/{key}"));
    result.extend(Image::load(store, key)?.objects());
    if let Some(key) = head["garbage"].as_str() {
        result.insert(format!("retired/{key}"));
    }
    Ok(result)
}
pub fn select(
    store: &Store,
    snapshot: &Object,
    head: &Value,
    prepared: Prepared,
    published_since_export: BTreeSet<String>,
    segment: usize,
    system: u64,
    data: &std::path::Path,
) -> Result<(Object, Value, usize)> {
    let end = num(head, "end")?;
    let base = prepared.start - prepared.start % segment as u64;
    if prepared.timeline as u64 != num(head, "timeline")?
        || prepared.end > end
        || prepared.start <= num(head, "start")?
    {
        return Err("snapshot selection precedes publication or has wrong timeline".into());
    }
    // The worker inventories the old snapshot/history. The publisher adds WAL
    // appended since that inventory, so selection does not scan S3 history.
    let mut old_objects = prepared.old_objects;
    old_objects.extend(published_since_export);
    let mut new_objects = prepared.new_objects;
    new_objects.insert(format!("snapshot-index/{}", prepared.image));
    let mut tail = Value::Null;
    let mut pos = base;
    let mut count = 0;
    let mut record = 0;
    while pos < end {
        let read_base = pos - pos % segment as u64;
        let available = end.min(pos + 64 * 1024 * 1024);
        let mut bytes = vec![0; (available - read_base) as usize];
        if !xlogutils::memory_wal::read(prepared.timeline, read_base, &mut bytes) {
            return Err("snapshot selection missing retained WAL".into());
        }
        let (last, complete) = decode::last_record(
            &bytes,
            read_base,
            available,
            pos,
            system,
            prepared.timeline,
            segment,
        )?;
        if complete <= pos {
            return Err("snapshot WAL record exceeds publication bound".into());
        }
        record = last;
        let chunk = store.immutable(
            "chunks",
            &bytes[(pos - read_base) as usize..(complete - read_base) as usize],
        )?;
        tail = json!(store.immutable("descriptors", &serde_json::to_vec(&json!({"cluster":head["cluster"],"timeline":head["timeline"],"start":pos,"end":complete,"record_start":record,"previous":tail,"chunk":chunk}))?)?);
        new_objects.insert(format!("chunks/{chunk}"));
        new_objects.insert(format!(
            "descriptors/{}",
            tail.as_str().ok_or("missing new tail")?
        ));
        pos = complete;
        count += 1;
    }
    if record != num(head, "record_start")? {
        return Err("snapshot WAL does not reach acknowledged frontier".into());
    }
    let root_history = if prepared.timeline > 1 {
        json!(store.immutable(
            "histories",
            &fs::read(data.join(format!("pg_wal/{:08X}.history", prepared.timeline)))?
        )?)
    } else {
        Value::Null
    };
    if let Some(key) = root_history.as_str() {
        new_objects.insert(format!("histories/{key}"));
    }
    let backup = store.immutable("backups", &serde_json::to_vec(&json!({"version":2,"cluster":head["cluster"],"timeline":prepared.timeline,"start":prepared.start,"end":prepared.end,"manifest":prepared.manifest,"image":prepared.image,"archive_start":base,"seed_end":end,"seed_record_start":record,"anchor":tail,"root_history":root_history}))?)?;
    let next = json!({"version":2,"cluster":head["cluster"],"timeline":head["timeline"],"start":base,"end":end,"record_start":record,"tail":tail,"backup":backup,"epoch":head["epoch"],"revision":fresh()?});
    new_objects.insert(format!("backups/{backup}"));
    let retired = old_objects
        .difference(&new_objects)
        .cloned()
        .collect::<Vec<_>>();
    let garbage = store.immutable("retired", &serde_json::to_vec(&retired)?)?;
    let mut next = next;
    next["garbage"] = json!(garbage);
    next["generation"] = json!(head["generation"].as_u64().unwrap_or(0) + 1);
    let selected = store.conditional("head", &serde_json::to_vec(&next)?, Some(snapshot))?;
    xlogutils::memory_wal::advance_archive_floor(base);
    Ok((selected, next, count))
}
fn cleanup(store: &Store, head: &Value) -> Result<()> {
    let Some(key) = head["garbage"].as_str() else {
        return Ok(());
    };
    let retired: Vec<String> = serde_json::from_slice(&store.verified("retired", key)?)?;
    if retired.len() > 100000 {
        return Err("retirement inventory limit".into());
    }
    validate_retirement(&retired, &objects(store, head)?)?;
    // A successor only extends this selected state. Retired object names cannot
    // become live again (backup payloads have generation-specific names).
    for key in retired {
        postgres_seams::check_for_interrupts::call()?;
        store.delete(&key)?;
    }
    Ok(())
}

fn validate_retirement(retired: &[String], live: &BTreeSet<String>) -> Result<()> {
    if retired
        .iter()
        .any(|key| !crate::http::owned_key(key) || live.contains(key))
    {
        return Err("retirement journal includes a protected or unsupported object".into());
    }
    Ok(())
}

/// Called during verified recovery, before starting backend threads. The exact
/// head CAS excludes competing replacements; the operator must already have
/// stopped the previous machine. No uploads or SQL run during this sweep.
pub fn reclaim_abandoned(
    store: &Store,
    snapshot: &Object,
    head: &Value,
) -> Result<(Object, Value)> {
    let live = objects(store, head)?;
    let mut claimed_head = head.clone();
    claimed_head["epoch"] = json!(fresh()?);
    claimed_head["revision"] = json!(fresh()?);
    let claimed = store.conditional("head", &serde_json::to_vec(&claimed_head)?, Some(snapshot))?;
    let mut after = None;
    loop {
        if store.required("head")? != claimed {
            return Err("ownership changed during orphan cleanup".into());
        }
        let keys = store.list_after(after.as_deref())?;
        if keys.is_empty() {
            break;
        }
        for key in &keys {
            if crate::http::owned_key(key) && !live.contains(key) {
                store.delete(key)?;
            }
        }
        after = keys.last().cloned();
    }
    if store.required("head")? != claimed {
        return Err("ownership changed during orphan cleanup".into());
    }
    Ok((claimed, claimed_head))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_cannot_delete_shared_pages_or_recovery_metadata() {
        let page = format!("backup-chunks/{}", "a".repeat(64));
        let root = format!("snapshot-index/{}", "b".repeat(64));
        let live = BTreeSet::from([page.clone(), root.clone()]);
        let dead = format!("chunks/{}", "c".repeat(64));
        assert!(validate_retirement(&[dead.clone()], &live).is_ok());
        assert!(validate_retirement(&[dead.clone(), page], &live).is_err());
        assert!(validate_retirement(&[dead, root], &live).is_err());
        assert!(validate_retirement(&["head".into()], &live).is_err());
        assert!(validate_retirement(&["chunks/../head".into()], &live).is_err());
    }
}
