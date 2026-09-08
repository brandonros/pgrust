use crate::http::{Object, Store};
use crate::{Result, digest, fresh};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_CHUNKS: usize = 10000;
const MAX_TIMELINES: usize = 32;
pub fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("invalid archive integer: {k}").into())
}
pub fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| format!("invalid archive string: {k}").into())
}
pub fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > 1024 * 1024 {
        return Err("archive metadata limit exceeded".into());
    }
    Ok(serde_json::from_slice(bytes)?)
}
pub fn heads(head: &Value) -> Result<Vec<Value>> {
    let mut nodes = vec![head.clone()];
    loop {
        let child = nodes.last().unwrap();
        let version = num(child, "version")?;
        if version != 2
            || num(child, "timeline")? == 0
            || num(child, "timeline")? > u32::MAX as u64
            || num(child, "start")? == 0
            || num(child, "start")? > num(child, "end")?
        {
            return Err(
                "unsupported or invalid archive head: version 2 flat snapshots are required".into(),
            );
        }
        text(child, "cluster")?;
        text(child, "epoch")?;
        text(child, "revision")?;
        if child["transition"].is_null() {
            break;
        }
        if nodes.len() >= MAX_TIMELINES {
            return Err("timeline limit exceeded".into());
        }
        let parent = &child["transition"]["parent"];
        if ["version", "backup", "cluster", "start"]
            .iter()
            .any(|k| parent[k] != child[k])
            || num(parent, "timeline")? >= num(child, "timeline")?
            || num(parent, "end")? != num(&child["transition"], "fork")?
            || num(parent, "end")? > num(child, "end")?
            || num(parent, "end")? <= num(child, "start")?
            || parent["tail"].is_null()
            || num(parent, "record_start")? < num(parent, "start")?
            || num(parent, "record_start")? >= num(parent, "end")?
            || (parent["end"] == child["end"]
                && (parent["tail"] != child["tail"]
                    || parent["record_start"] != child["record_start"]))
        {
            return Err("invalid parent history binding".into());
        }
        nodes.push(parent.clone());
    }
    Ok(nodes)
}
pub fn history_rows(bytes: &[u8]) -> Result<Vec<(u64, u64)>> {
    if bytes.len() > 65536 {
        return Err("timeline history limit".into());
    }
    let mut rows = Vec::new();
    for line in std::str::from_utf8(bytes)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let mut words = line.split_whitespace();
        let t: u32 = words.next().ok_or("missing timeline")?.parse()?;
        let l = crate::lsn(words.next().ok_or("missing fork LSN")?)?;
        if t == 0 {
            return Err("invalid history timeline".into());
        }
        rows.push((t as u64, l));
    }
    Ok(rows)
}
pub fn check_history(bytes: &[u8], parent: &Value, root: &[u8]) -> Result<()> {
    let mut expected = history_rows(root)?;
    for h in heads(parent)?.iter().rev() {
        expected.push((num(h, "timeline")?, num(h, "end")?));
    }
    if history_rows(bytes)? != expected {
        return Err("native timeline history differs from exact restored parent".into());
    }
    Ok(())
}
pub(crate) fn eligibility(
    store: &Store,
    head: &Value,
    nodes: &[Value],
) -> Result<(Value, Vec<u8>)> {
    let info = parse(&store.verified("backups", text(head, "backup")?)?)?;
    if !info["parent"].is_null() || info["image"].as_str().is_none() {
        return Err("unsupported archive: a flat native snapshot is required".into());
    }
    let root = nodes.last().unwrap();
    if info["version"] != head["version"]
        || info["cluster"] != head["cluster"]
        || info["timeline"] != root["timeline"]
        || !(num(head, "start")? <= num(&info, "start")?
            && num(&info, "start")? < num(&info, "end")?
            && num(&info, "end")? <= num(root, "end")?)
        || num(head, "record_start")? < num(&info, "start")?
    {
        return Err("backup does not match published history".into());
    }
    let mut history = Vec::new();
    if info["archive_start"] != head["start"]
        || num(&info, "seed_end")? < num(&info, "end")?
        || num(&info, "seed_end")? > num(root, "end")?
        || num(&info, "seed_record_start")? < num(&info, "start")?
        || num(&info, "seed_record_start")? >= num(&info, "seed_end")?
    {
        return Err("invalid backup seed bounds".into());
    }
    if num(root, "timeline")? > 1 {
        history = store.verified("histories", text(&info, "root_history")?)?;
        let rows = history_rows(&history)?;
        if rows.is_empty()
            || rows[0].0 != 1
            || rows.last().unwrap().0 >= num(root, "timeline")?
            || rows.last().unwrap().1 > num(head, "start")?
            || rows.windows(2).any(|w| w[0].0 >= w[1].0 || w[0].1 > w[1].1)
        {
            return Err("invalid root timeline history".into());
        }
    } else if !info["root_history"].is_null() {
        return Err("unexpected root history".into());
    }
    Ok((info, history))
}
fn check_manifest(info: &Value, manifest: &Value) -> Result<()> {
    let ranges = manifest["WAL-Ranges"]
        .as_array()
        .ok_or("invalid backup ranges")?;
    if ranges.len() != 1
        || num(manifest, "System-Identifier")?.to_string() != text(info, "cluster")?
        || num(&ranges[0], "Timeline")? != num(info, "timeline")?
        || crate::lsn(text(&ranges[0], "Start-LSN")?)? != num(info, "start")?
        || crate::lsn(text(&ranges[0], "End-LSN")?)? != num(info, "end")?
    {
        return Err("backup manifest disagrees with eligibility".into());
    }
    Ok(())
}
fn restore_backup(store: &Store, info: &Value, stage: &Path) -> Result<PathBuf> {
    let image = crate::image::Image::load(store, text(info, "image")?)?;
    if digest(&image.manifest()) != text(info, "manifest")? {
        return Err("snapshot manifest mismatch".into());
    }
    let target = stage.join("snapshot");
    // The inventory is content-addressed and restore verifies each object's
    // bytes before writing. Validate native identity/ranges without rereading
    // and hashing every materialized file a second time.
    check_manifest(info, &serde_json::from_slice(&image.manifest())?)?;
    image.restore(store, &target)?;
    if fs::read_to_string(target.join("backup_label"))?.contains("INCREMENTAL FROM ") {
        return Err("flat snapshot contains an incremental backup label".into());
    }
    Ok(target)
}
pub struct Restored {
    pub snapshot: Object,
    pub head: Value,
    pub root_history: Vec<u8>,
    pub chunks: usize,
    pub system: u64,
    pub segment: usize,
    pub segments: BTreeMap<(u32, u64), Vec<u8>>,
    pub data: PathBuf,
}
pub fn restore(store: &Store, snapshot: Object, stage: &Path, limit: usize) -> Result<Restored> {
    let head = parse(&snapshot.body)?;
    let nodes = heads(&head)?;
    if nodes.len() >= MAX_TIMELINES {
        return Err("timeline history capacity exhausted".into());
    }
    let (info, root_history) = eligibility(store, &head, &nodes)?;
    let data = restore_backup(store, &info, stage)?;
    let (control, valid) =
        controldata_utils::get_controlfile(data.to_str().ok_or("non UTF-8 data path")?)?;
    let segment = control.xlog_seg_size as usize;
    let system = control.system_identifier;
    if !valid
        || control.pg_control_version != controldata_utils::PG_CONTROL_VERSION
        || system.to_string() != text(&head, "cluster")?
        || !(1024 * 1024..=1024 * 1024 * 1024).contains(&segment)
        || !segment.is_power_of_two()
        || num(&head, "start")? % segment as u64 != 0
    {
        return Err("invalid control file or WAL segment size".into());
    }
    let mut histories = BTreeMap::new();
    if !root_history.is_empty() {
        histories.insert(
            num(nodes.last().unwrap(), "timeline")? as u32,
            root_history.clone(),
        );
    }
    for pair in nodes.windows(2) {
        let h = store.verified("histories", text(&pair[0]["transition"], "history")?)?;
        check_history(&h, &pair[1], &root_history)?;
        histories.insert(num(&pair[0], "timeline")? as u32, h);
    }
    let mut tail = head["tail"].clone();
    let mut end = num(&head, "end")?;
    let mut owner = 0;
    let mut anchored = false;
    let mut chain = Vec::new();
    while !tail.is_null() {
        if chain.len() >= MAX_CHUNKS {
            return Err("WAL history capacity exceeded".into());
        }
        while owner + 1 < nodes.len() && end == num(&nodes[owner + 1], "end")? {
            if tail != nodes[owner + 1]["tail"] {
                return Err("incorrect timeline parent tail".into());
            }
            owner += 1;
        }
        let d = parse(&store.verified("descriptors", tail.as_str().ok_or("invalid tail")?)?)?;
        let start = num(&d, "start")?;
        let rec = num(&d, "record_start")?;
        if d["cluster"] != head["cluster"]
            || d["timeline"] != nodes[owner]["timeline"]
            || num(&d, "end")? != end
            || start < num(&head, "start")?
            || start > rec
            || rec >= end
            || end - start > 64 * 1024 * 1024
            || (owner + 1 < nodes.len() && start < num(&nodes[owner + 1], "end")?)
            || (end == num(&nodes[owner], "end")?
                && d["record_start"] != nodes[owner]["record_start"])
            || (chain.is_empty() && d["record_start"] != head["record_start"])
        {
            return Err("discontinuous WAL history".into());
        }
        if tail == info["anchor"] {
            anchored = true;
            if d["end"] != info["seed_end"]
                || d["record_start"] != info["seed_record_start"]
                || d["timeline"] != info["timeline"]
            {
                return Err("backup anchor mismatch".into());
            }
        }
        tail = d["previous"].clone();
        end = start;
        chain.push(d);
    }
    if !anchored || end != num(&head, "start")? || owner + 1 != nodes.len() {
        return Err("incomplete WAL history or missing backup anchor".into());
    }
    let mut segments: BTreeMap<(u32, u64), Vec<u8>> = BTreeMap::new();
    let mut parent: Option<&Value> = None;
    for node in nodes.iter().rev() {
        let t = num(node, "timeline")? as u32;
        if let Some(p) = parent {
            let fork = num(p, "end")?;
            let off = (fork % segment as u64) as usize;
            if off > 0 {
                let prefix = segments
                    .get(&(num(p, "timeline")? as u32, fork / segment as u64))
                    .ok_or("missing parent segment")?
                    .clone();
                alloc(&mut segments, t, fork / segment as u64, segment, limit)?[..off]
                    .copy_from_slice(&prefix[..off]);
            }
        }
        for d in chain
            .iter()
            .rev()
            .filter(|d| d["timeline"] == node["timeline"])
        {
            let body = store.verified("chunks", text(d, "chunk")?)?;
            let mut pos = num(d, "start")?;
            let end = num(d, "end")?;
            if body.len() as u64 != end - pos {
                return Err("WAL chunk length mismatch".into());
            }
            let mut consumed = 0;
            while consumed < body.len() {
                let off = (pos % segment as u64) as usize;
                let count = (segment - off).min(body.len() - consumed);
                alloc(&mut segments, t, pos / segment as u64, segment, limit)?[off..off + count]
                    .copy_from_slice(&body[consumed..consumed + count]);
                pos += count as u64;
                consumed += count;
            }
        }
        let base = parent
            .map(|p| num(p, "end"))
            .transpose()?
            .unwrap_or(num(&head, "start")?);
        let end = num(node, "end")?;
        if end > base {
            let first = parent.map(|p| num(p, "end")).transpose()?.unwrap_or(base);
            let bytes = span(
                &segments,
                t,
                base - base % segment as u64,
                end,
                segment,
                limit,
            )?;
            let last = crate::decode::last_record(
                &bytes,
                base - base % segment as u64,
                end,
                first,
                system,
                t,
                segment,
            )?;
            if last != (num(node, "record_start")?, end) {
                return Err("native WAL validation disagrees with archive boundary".into());
            }
        }
        if let Some(h) = histories.get(&t) {
            fs::write(data.join(format!("pg_wal/{t:08X}.history")), h)?;
        }
        parent = Some(node);
    }
    Ok(Restored {
        snapshot,
        head,
        root_history,
        chunks: chain.len(),
        system,
        segment,
        segments,
        data,
    })
}
fn alloc(
    s: &mut BTreeMap<(u32, u64), Vec<u8>>,
    t: u32,
    n: u64,
    size: usize,
    limit: usize,
) -> Result<&mut Vec<u8>> {
    if !s.contains_key(&(t, n)) {
        if s.len() >= limit / size {
            return Err("memory WAL recovery capacity exhausted".into());
        }
        s.insert((t, n), vec![0; size]);
    }
    Ok(s.get_mut(&(t, n)).unwrap())
}
pub fn span(
    s: &BTreeMap<(u32, u64), Vec<u8>>,
    t: u32,
    mut start: u64,
    end: u64,
    size: usize,
    limit: usize,
) -> Result<Vec<u8>> {
    if end < start || end - start > limit as u64 {
        return Err("WAL read capacity exceeded".into());
    }
    let mut out = Vec::with_capacity((end - start) as usize);
    while start < end {
        let part = s
            .get(&(t, start / size as u64))
            .ok_or("missing WAL segment")?;
        let off = (start % size as u64) as usize;
        let count = (size - off).min((end - start) as usize);
        out.extend_from_slice(&part[off..off + count]);
        start += count as u64;
    }
    Ok(out)
}
pub fn fork(
    store: &Store,
    snapshot: &Object,
    parent: &Value,
    t: u32,
    history: &[u8],
    root: &[u8],
) -> Result<(Object, Value)> {
    if t as u64 <= num(parent, "timeline")? {
        return Err("recovery did not produce a new native timeline".into());
    }
    check_history(history, parent, root)?;
    let key = store.immutable("histories", history)?;
    let mut head = parent.clone();
    head["timeline"] = json!(t);
    head["transition"] = json!({"parent":parent,"history":key,"fork":num(parent,"end")?});
    head["epoch"] = json!(fresh()?);
    head["revision"] = json!(fresh()?);
    let claimed = store.conditional("head", &serde_json::to_vec(&head)?, Some(snapshot))?;
    Ok((claimed, head))
}
pub fn publish(
    store: &Store,
    snapshot: &Object,
    head: &Value,
    data: &[u8],
    record: u64,
) -> Result<(Object, Value)> {
    let start = num(head, "end")?;
    let end = start
        .checked_add(data.len() as u64)
        .ok_or("WAL position overflow")?;
    if data.is_empty() || data.len() > 64 * 1024 * 1024 || record < start || record >= end {
        return Err("invalid WAL publication boundary".into());
    }
    let chunk = store.immutable("chunks", data)?;
    let desc = json!({"cluster":head["cluster"],"timeline":head["timeline"],"start":start,"end":end,"record_start":record,"previous":head["tail"],"chunk":chunk});
    let tail = store.immutable("descriptors", &serde_json::to_vec(&desc)?)?;
    let mut next = head.clone();
    next["end"] = json!(end);
    next["record_start"] = json!(record);
    next["tail"] = json!(tail);
    next["revision"] = json!(fresh()?);
    let out = store.conditional("head", &serde_json::to_vec(&next)?, Some(snapshot))?;
    Ok((out, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> Value {
        json!({"version":2,"cluster":"42","timeline":1,"start":16777216,"end":16785408,"record_start":16780000,"tail":"abc","epoch":"e","revision":"r"})
    }
    #[test]
    fn timeline_requires_exact_parent() {
        let parent = root();
        let mut child = parent.clone();
        child["timeline"] = json!(2);
        child["transition"] = json!({"parent":parent,"fork":16785408,"history":"abc"});
        assert_eq!(heads(&child).unwrap().len(), 2);
        child["tail"] = json!("wrong");
        assert!(heads(&child).is_err());
        let h = b"1\t0/1002000\trecovery\n";
        check_history(h, &root(), b"").unwrap();
        assert!(check_history(b"1\t0/1002001\twrong\n", &root(), b"").is_err());
    }
    #[test]
    fn obsolete_archive_version_is_refused() {
        let mut head = root();
        head["version"] = json!(1);
        assert!(heads(&head).is_err());
    }
    #[test]
    fn retained_span_refuses_holes_and_capacity() {
        let s = BTreeMap::from([((1, 1), vec![1; 16]), ((1, 2), vec![2; 16])]);
        assert_eq!(
            span(&s, 1, 24, 40, 16, 32).unwrap(),
            [vec![1; 8], vec![2; 8]].concat()
        );
        assert!(span(&s, 1, 24, 56, 16, 32).is_err());
        assert!(span(&s, 1, 16, 48, 16, 16).is_err());
    }
}
