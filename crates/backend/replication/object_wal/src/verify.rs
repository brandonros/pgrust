//! Verify the materialized native snapshot before recovery can claim ownership.
use crate::{
    Result,
    archive::{num, text},
};
use manifest::{PgChecksumContext, PgChecksumType};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path};
const LIMIT: u64 = 256 * 1024 * 1024;
fn fail(s: &str) -> Box<dyn std::error::Error> {
    s.into()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|n| format!("{n:02x}")).collect()
}
fn algorithm(s: &str) -> Result<PgChecksumType> {
    Ok(match s {
        "CRC32C" => PgChecksumType::Crc32c,
        "SHA224" => PgChecksumType::Sha224,
        "SHA256" => PgChecksumType::Sha256,
        "SHA384" => PgChecksumType::Sha384,
        "SHA512" => PgChecksumType::Sha512,
        _ => return Err(fail("unsupported file checksum")),
    })
}
fn checksum_file(path: &Path, ty: PgChecksumType) -> Result<String> {
    let mut file = File::open(path)?;
    let mut ctx = PgChecksumContext::init(ty);
    let mut buf = [0; 32768];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let mut out = [0; 64];
    let n = ctx.finalize(&mut out);
    Ok(hex(&out[..n]))
}
fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('\0')
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
        && Path::new(s)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}
pub(crate) fn inspect(root: &Path) -> Result<Value> {
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(fail("symlink artifact root"));
    }
    if fs::symlink_metadata(root.join("backup_manifest"))?
        .file_type()
        .is_symlink()
        || fs::metadata(root.join("backup_manifest"))?.len() > 64 * 1024 * 1024
    {
        return Err(fail("manifest input type/size limit"));
    }
    let bytes = fs::read(root.join("backup_manifest"))?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(fail("manifest input limit"));
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    let end = bytes.len() - usize::from(bytes.last() == Some(&b'\n'));
    let start = bytes[..end]
        .iter()
        .rposition(|b| *b == b'\n')
        .ok_or("missing checksum line")?
        + 1;
    if !std::str::from_utf8(&bytes[start..])?
        .trim_start()
        .starts_with("\"Manifest-Checksum\"")
        || text(&value, "Manifest-Checksum")? != hex(&pg_sha2::sha256(&bytes[..start]))
        || num(&value, "PostgreSQL-Backup-Manifest-Version")? != 2
    {
        return Err(fail("invalid manifest checksum/version"));
    }
    let mut files = BTreeSet::new();
    let mut total = 0u64;
    for entry in value["Files"].as_array().ok_or("invalid file inventory")? {
        let path = text(entry, "Path")?; // Explicit bounded UTF-8 artifact workflow.
        if !safe_path(path)
            || path.starts_with("pg_tblspc/")
            || (path.starts_with("pg_wal/")
                && !(path.starts_with("pg_wal/archive_status/")
                    && path.ends_with(".done")
                    && num(entry, "Size")? == 0))
            || path == "backup_manifest"
        {
            return Err(fail("unsupported backup path"));
        }
        let size = num(entry, "Size")?;
        total = total.checked_add(size).ok_or("backup size overflow")?;
        if total > LIMIT || files.len() >= 10000 {
            return Err(fail("backup size/member limit"));
        }
        let mut current = root.to_path_buf();
        for part in Path::new(path).components() {
            current.push(part);
            if fs::symlink_metadata(&current)?.file_type().is_symlink() {
                return Err(fail("symlink in artifact"));
            }
        }
        let meta = fs::metadata(&current)?;
        if !meta.is_file() || meta.len() != size {
            return Err(fail("backup file size mismatch"));
        }
        // Require file checksums for bucket recovery, even though core exports
        // can deliberately omit them. Refuse instead of trusting missing checks.
        let ty = algorithm(text(entry, "Checksum-Algorithm")?)?;
        if checksum_file(&current, ty)? != text(entry, "Checksum")? {
            return Err(fail("backup file checksum mismatch"));
        }
        if !files.insert(path.to_string()) {
            return Err(fail("duplicate file"));
        }
    }
    if !files.contains("backup_label") || !files.contains("global/pg_control") {
        return Err(fail("missing native backup metadata"));
    }
    let control = fs::read(root.join("global/pg_control"))?;
    if control.len() < 8
        || u64::from_ne_bytes(control[..8].try_into()?) != num(&value, "System-Identifier")?
    {
        return Err(fail("manifest/control system identifier mismatch"));
    }
    let label = fs::read_to_string(root.join("backup_label"))?;
    if label.contains("INCREMENTAL FROM ") {
        return Err(fail("flat snapshot contains an incremental backup label"));
    }
    Ok(value)
}
