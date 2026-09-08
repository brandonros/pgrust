//! A flat inventory of native backup bytes. Incremental pages replace references;
//! unchanged pages keep their objects, without retaining ancestor inventories.
use crate::{
    Result,
    archive::{num, text},
    create::Capture,
    digest, fresh,
    http::Store,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read, Write},
    path::{Component, Path},
};
const PAGE: usize = 8192;
const CHUNK: usize = 128 * 1024;
const LIMIT: usize = 256 * 1024 * 1024;
const SALT: usize = 32;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Piece {
    key: String,
    offset: usize,
    length: usize,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Image {
    files: BTreeMap<String, Vec<Piece>>,
    dirs: BTreeSet<String>,
    system: u64,
    ranges: Value,
}
fn safe(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\0')
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && !path.starts_with("pg_tblspc/")
}
fn size(pieces: &[Piece]) -> usize {
    pieces.iter().map(|p| p.length).sum()
}
fn manifest(system: u64, files: Value, ranges: &Value) -> Vec<u8> {
    let body = format!(
        "{{\"PostgreSQL-Backup-Manifest-Version\":2,\"System-Identifier\":{system},\n\"Files\":{files},\n\"WAL-Ranges\":{ranges},\n"
    );
    format!(
        "{body}\"Manifest-Checksum\":\"{}\"}}\n",
        digest(body.as_bytes())
    )
    .into_bytes()
}
impl Image {
    pub fn load(store: &Store, key: &str) -> Result<Self> {
        let image: Self = serde_json::from_slice(&store.verified("snapshot-index", key)?)?;
        image.validate()?;
        Ok(image)
    }
    fn validate(&self) -> Result<()> {
        let mut total = 0usize;
        let mut count = 0;
        if self.files.len() > 10000 || self.dirs.len() > 10000 || self.dirs.iter().any(|p| !safe(p))
        {
            return Err("snapshot inventory limit/path".into());
        }
        for (path, pieces) in &self.files {
            if !safe(path)
                || path == "backup_manifest"
                || path.starts_with("pg_wal/")
                || self.dirs.contains(path)
            {
                return Err("unsupported snapshot file".into());
            }
            for (i, p) in pieces.iter().enumerate() {
                total = total
                    .checked_add(p.length)
                    .ok_or("snapshot size overflow")?;
                count += 1;
                if !crate::http::address(&p.key)
                    || p.offset < SALT
                    || p.offset > SALT + CHUNK
                    || p.length == 0
                    || p.length > PAGE
                    || p.offset + p.length > SALT + CHUNK
                    || (i + 1 < pieces.len() && p.length != PAGE)
                    || total > LIMIT
                    || count > LIMIT / PAGE + 10000
                {
                    return Err("invalid snapshot byte reference/size".into());
                }
            }
            for ancestor in Path::new(path).ancestors().skip(1) {
                if self
                    .files
                    .contains_key(ancestor.to_str().ok_or("snapshot pathname")?)
                {
                    return Err("snapshot file used as directory".into());
                }
            }
        }
        if !self.files.contains_key("backup_label") || !self.files.contains_key("global/pg_control")
        {
            return Err("snapshot missing native metadata".into());
        }
        Ok(())
    }
    pub fn manifest(&self) -> Vec<u8> {
        manifest(
            self.system,
            json!(
                self.files
                    .iter()
                    .map(|(p, b)| json!({"Path":p,"Size":size(b)}))
                    .collect::<Vec<_>>()
            ),
            &self.ranges,
        )
    }
    pub fn objects(&self) -> BTreeSet<String> {
        self.files
            .values()
            .flatten()
            .map(|p| format!("backup-chunks/{}", p.key))
            .collect()
    }
    pub fn save(&self, store: &Store) -> Result<String> {
        self.validate()?;
        store.immutable("snapshot-index", &serde_json::to_vec(self)?)
    }
    pub fn restore(&self, store: &Store, target: &Path) -> Result<()> {
        self.validate()?;
        fs::create_dir(target)?;
        for dir in &self.dirs {
            fs::create_dir_all(target.join(dir))?;
        }
        let mut inventory = Vec::new();
        let mut cached = (String::new(), Vec::new());
        for (path, pieces) in &self.files {
            let dest = target.join(path);
            fs::create_dir_all(dest.parent().ok_or("snapshot parent")?)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dest)?;
            let mut hash = manifest::PgChecksumContext::init(manifest::PgChecksumType::Sha256);
            for p in pieces {
                if cached.0 != p.key {
                    cached = (p.key.clone(), store.verified("backup-chunks", &p.key)?);
                }
                let bytes = cached
                    .1
                    .get(p.offset..p.offset + p.length)
                    .ok_or("short snapshot object")?;
                file.write_all(bytes)?;
                hash.update(bytes);
            }
            let mut checksum = [0; 32];
            hash.finalize(&mut checksum);
            inventory.push(json!({"Path":path,"Size":size(pieces),"Checksum-Algorithm":"SHA256","Checksum":checksum.iter().map(|n| format!("{n:02x}")).collect::<String>()}));
        }
        fs::write(
            target.join("backup_manifest"),
            manifest(self.system, json!(inventory), &self.ranges),
        )?;
        Ok(())
    }
}
fn upload(store: &Store, generation: &str, bytes: &[u8]) -> Result<Vec<Piece>> {
    let mut pieces = Vec::new();
    for chunk in bytes.chunks(CHUNK) {
        // Generation salt prevents a delayed GC from deleting a later upload of
        // identical bytes. Live references may be shared; retired names never recur.
        let mut body = generation.as_bytes().to_vec();
        body.extend_from_slice(chunk);
        let key = store.immutable("backup-chunks", &body)?;
        for (i, page) in chunk.chunks(PAGE).enumerate() {
            pieces.push(Piece {
                key: key.clone(),
                offset: SALT + i * PAGE,
                length: page.len(),
            });
        }
    }
    Ok(pieces)
}
fn patch(
    previous: &[Piece],
    bytes: &[u8],
    changed: Vec<Piece>,
    mut zero: impl FnMut() -> Result<Piece>,
) -> Result<Vec<Piece>> {
    if bytes.len() < 12 {
        return Err("short incremental header".into());
    }
    let word = |i| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
    let (magic, count, truncation) = (word(0), word(4), word(8));
    if magic != 0xd3ae1f0d || count > 131072 || truncation > 131072 {
        return Err("invalid incremental header".into());
    }
    let offset = if count == 0 {
        12
    } else {
        (12 + count * 4).div_ceil(PAGE) * PAGE
    };
    if bytes.len() != offset + count * PAGE || changed.len() != count {
        return Err("incremental length mismatch".into());
    }
    let mut blocks = Vec::new();
    for i in 0..count {
        let b = word(12 + i * 4);
        if b >= 131072 || blocks.last().is_some_and(|last| *last >= b) {
            return Err("invalid incremental block list".into());
        }
        blocks.push(b);
    }
    let length = truncation.max(blocks.last().map_or(0, |b| b + 1));
    if length > LIMIT / PAGE {
        return Err("snapshot relation limit".into());
    }
    let mut result = Vec::new();
    let mut changed = blocks.into_iter().zip(changed).peekable();
    for b in 0..length {
        if changed.peek().is_some_and(|(block, _)| *block == b) {
            result.push(changed.next().unwrap().1);
        } else if b < truncation && b < previous.len() {
            let p = &previous[b];
            if p.length != PAGE {
                return Err("partial predecessor page".into());
            }
            result.push(p.clone());
        } else {
            // Extension can add zero pages without WAL, even below truncation.
            // Match native pg_combinebackup when the prior file ends sooner.
            result.push(zero()?);
        }
    }
    Ok(result)
}
pub fn export(store: &Store, capture: &Capture, parent: Option<&Image>) -> Result<Image> {
    let source: Value = serde_json::from_slice(&capture.manifest)?;
    let system = num(&source, "System-Identifier")?;
    let ranges = source["WAL-Ranges"].clone();
    if parent.is_some_and(|p| p.system != system) {
        return Err("snapshot cluster mismatch".into());
    }
    let generation = fresh()?;
    let mut image = Image {
        files: BTreeMap::new(),
        dirs: BTreeSet::new(),
        system,
        ranges,
    };
    let mut archive = tar::Archive::new(Cursor::new(&capture.archive));
    let mut seen = BTreeSet::new();
    for member in archive.entries()? {
        let mut member = member?;
        let path = member
            .path()?
            .to_str()
            .ok_or("non UTF-8 snapshot pathname")?
            .trim_end_matches('/')
            .to_string();
        if !safe(&path) || !seen.insert(path.clone()) || seen.len() > 20000 {
            return Err("invalid snapshot member".into());
        }
        if member.header().entry_type().is_dir() {
            image.dirs.insert(path);
            continue;
        }
        if !member.header().entry_type().is_file() || member.size() > LIMIT as u64 {
            return Err("unsupported snapshot member".into());
        }
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes)?;
        if path == "backup_manifest" {
            continue;
        }
        if path.starts_with("pg_wal/") {
            if path.starts_with("pg_wal/archive_status/")
                && path.ends_with(".done")
                && bytes.is_empty()
            {
                continue;
            }
            return Err("snapshot contains WAL file".into());
        }
        let name = Path::new(&path).file_name().unwrap().to_str().unwrap();
        let (dest, pieces) = if let Some(name) = name.strip_prefix("INCREMENTAL.") {
            if !(path.starts_with("base/") || path.starts_with("global/")) || bytes.len() < 12 {
                return Err("invalid incremental member".into());
            }
            let dest = Path::new(&path)
                .with_file_name(name)
                .to_str()
                .unwrap()
                .to_string();
            let previous = parent
                .and_then(|p| p.files.get(&dest))
                .ok_or("missing incremental predecessor")?;
            let count = u32::from_ne_bytes(bytes[4..8].try_into()?) as usize;
            if count > 131072 {
                return Err("incremental block limit".into());
            }
            let offset = if count == 0 {
                12
            } else {
                (12 + count * 4).div_ceil(PAGE) * PAGE
            };
            let data = bytes.get(offset..).ok_or("short incremental data")?;
            let changed = upload(store, &generation, data)?;
            (
                dest,
                patch(previous, &bytes, changed, || {
                    Ok(upload(store, &generation, &[0; PAGE])?.remove(0))
                })?,
            )
        } else {
            if path == "backup_label" {
                bytes = std::str::from_utf8(&bytes)?
                    .lines()
                    .filter(|l| !l.starts_with("INCREMENTAL FROM "))
                    .map(|l| format!("{l}\n"))
                    .collect::<String>()
                    .into_bytes();
            }
            (path, upload(store, &generation, &bytes)?)
        };
        if image.files.insert(dest, pieces).is_some() {
            return Err("duplicate output snapshot file".into());
        }
    }
    image.validate()?;
    // The native exporter inventories all files, including unchanged relations.
    let expected = source["Files"]
        .as_array()
        .ok_or("missing native inventory")?;
    for file in expected {
        let path = text(file, "Path")?;
        let name = Path::new(path)
            .file_name()
            .ok_or("missing native name")?
            .to_str()
            .ok_or("invalid native name")?;
        let dest =
            Path::new(path).with_file_name(name.strip_prefix("INCREMENTAL.").unwrap_or(name));
        if !path.starts_with("pg_wal/archive_status/")
            && !image
                .files
                .contains_key(dest.to_str().ok_or("invalid native path")?)
        {
            return Err("snapshot is missing native inventory member".into());
        }
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn piece(n: usize) -> Piece {
        Piece {
            key: format!("{n:064x}"),
            offset: SALT,
            length: PAGE,
        }
    }
    fn increment(truncation: u32, blocks: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        for word in [0xd3ae1f0du32, blocks.len() as u32, truncation]
            .into_iter()
            .chain(blocks.iter().copied())
        {
            out.extend_from_slice(&word.to_ne_bytes());
        }
        if !blocks.is_empty() {
            out.resize(out.len().div_ceil(PAGE) * PAGE + blocks.len() * PAGE, 0);
        }
        out
    }
    #[test]
    fn native_increment_reuses_unchanged_pages_and_truncates() {
        let previous = vec![piece(1), piece(2), piece(3)];
        assert_eq!(
            patch(&previous, &increment(2, &[1]), vec![piece(4)], || panic!()).unwrap(),
            vec![piece(1), piece(4)]
        );
        assert_eq!(
            patch(&previous, &increment(1, &[]), vec![], || panic!()).unwrap(),
            vec![piece(1)]
        );
        assert!(
            patch(
                &previous,
                &increment(3, &[2, 1]),
                vec![piece(4), piece(5)],
                || panic!()
            )
            .is_err()
        );
    }
    #[test]
    fn extension_below_truncation_zeroes_pages_absent_from_predecessor() {
        // Native relation extension can add zero pages without a WAL record.
        // pg_combinebackup fills these even below the truncation boundary.
        let previous = vec![piece(1)];
        assert_eq!(
            patch(&previous, &increment(3, &[]), vec![], || Ok(piece(0))).unwrap(),
            vec![piece(1), piece(0), piece(0)]
        );
        assert_eq!(
            patch(&previous, &increment(4, &[2]), vec![piece(2)], || Ok(piece(0))).unwrap(),
            vec![piece(1), piece(0), piece(2), piece(0)]
        );
        let mut partial = piece(1);
        partial.length = 1;
        assert!(patch(&[partial], &increment(1, &[]), vec![], || Ok(piece(0))).is_err());
    }

    #[test]
    fn extension_zeroes_holes_without_resurrecting_truncated_pages() {
        let p = vec![piece(1), piece(2), piece(3)];
        assert_eq!(
            patch(&p, &increment(1, &[3]), vec![piece(4)], || Ok(piece(0))).unwrap(),
            vec![piece(1), piece(0), piece(0), piece(4)]
        );
    }
    #[test]
    fn repeated_updates_do_not_retain_an_ancestry_chain() {
        let mut p = vec![piece(1), piece(2)];
        for generation in 3..30 {
            p = patch(
                &p,
                &increment(2, &[1]),
                vec![piece(generation)],
                || panic!(),
            )
            .unwrap();
            assert_eq!(p, vec![piece(1), piece(generation)]);
        }
    }
}
