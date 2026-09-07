//! One-time publication from a clean, locked local database. Uses the native
//! backup exporter; SQL stays closed until the first conditional head succeeds.
use crate::{Result, archive, decode, digest, fresh, http::Store, pg_error};
use mcx::Mcx;
use serde_json::json;
use sink::{Bbsink, BbsinkOps, BbsinkState};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};
use types_error::PgResult;
const MAX_BACKUP: usize = 256 * 1024 * 1024;

pub fn seed(data: &Path, limit: usize) -> Result<()> {
    let (control, valid) =
        controldata_utils::get_controlfile(data.to_str().ok_or("non UTF-8 data directory")?)?;
    let segment = control.xlog_seg_size as usize;
    if !valid
        || control.state != controldata_utils::DB_SHUTDOWNED
        || control.pg_control_version != controldata_utils::PG_CONTROL_VERSION
        || control.catalog_version_no != controldata_utils::CATALOG_VERSION_NO
        || control.checkPointCopy.ThisTimeLineID != 1
        || control.checkPointCopy.redo != control.checkPoint
        || control.backupStartPoint != 0
        || control.backupEndRequired
        || !(1024 * 1024..=1024 * 1024 * 1024).contains(&segment)
        || !segment.is_power_of_two()
        || segment > limit / 8
    {
        return Err(
            "creation requires a cleanly shut down timeline-one database with a valid checkpoint"
                .into(),
        );
    }
    for name in [
        "recovery.signal",
        "standby.signal",
        "backup_label",
        "pgrust.memory_wal",
    ] {
        match fs::symlink_metadata(data.join(name)) {
            Ok(_) => return Err(format!("creation refuses {name}").into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let wal = data.join("pg_wal");
    if fs::symlink_metadata(&wal)?.file_type().is_symlink()
        || fs::read_dir(data.join("pg_tblspc"))?.next().is_some()
    {
        return Err("creation requires local WAL and no external tablespaces".into());
    }
    let seg = control.checkPoint / segment as u64;
    let base = seg * segment as u64;
    let per_id = 0x1_0000_0000u64 / segment as u64;
    let path = wal.join(format!("00000001{:08X}{:08X}", seg / per_id, seg % per_id));
    let meta = fs::symlink_metadata(&path)?;
    if !meta.is_file() || meta.len() != segment as u64 {
        return Err("invalid initial WAL segment".into());
    }
    let bytes = fs::read(path)?;
    let (record, end) = decode::first_record(
        &bytes,
        base,
        control.checkPoint,
        control.system_identifier,
        1,
        segment,
    )?;
    if record != control.checkPoint || end <= record {
        return Err("initial checkpoint WAL is incomplete".into());
    }
    xlogutils::memory_wal::initialize(BTreeMap::from([((1, seg), bytes)]), limit, segment)?;
    Ok(())
}

#[derive(Default)]
pub(crate) struct Capture {
    pub archive: Vec<u8>,
    pub manifest: Vec<u8>,
    pub start: u64,
    pub end: u64,
    pub timeline: u32,
}
struct Collector<'a> {
    mcx: Mcx<'a>,
    data: Rc<RefCell<Capture>>,
}
fn append(out: &mut Vec<u8>, bytes: &[u8], limit: usize) -> PgResult<()> {
    if bytes.len() > limit.saturating_sub(out.len()) {
        return Err(pg_error("native backup capture exceeds archive limit"));
    }
    out.extend_from_slice(bytes);
    Ok(())
}
impl<'a> BbsinkOps<'a> for Collector<'a> {
    fn begin_backup(&mut self, sink: &mut Bbsink<'a>, state: &mut BbsinkState) -> PgResult<()> {
        if state.tablespaces.len() != 1 {
            return Err(pg_error("object backup requires no tablespaces"));
        }
        sink.set_buffer(self.mcx, sink.buffer_length())?;
        let mut data = self.data.borrow_mut();
        data.start = state.startptr;
        data.timeline = state.starttli;
        Ok(())
    }
    fn begin_archive(
        &mut self,
        _: &mut Bbsink<'a>,
        _: &mut BbsinkState,
        name: &str,
    ) -> PgResult<()> {
        if name != "base.tar" {
            return Err(pg_error("unexpected native backup archive"));
        }
        Ok(())
    }
    fn archive_contents(
        &mut self,
        sink: &mut Bbsink<'a>,
        _: &mut BbsinkState,
        len: usize,
    ) -> PgResult<()> {
        append(
            &mut self.data.borrow_mut().archive,
            sink.buffer_slice(len),
            MAX_BACKUP,
        )
    }
    fn end_archive(&mut self, _: &mut Bbsink<'a>, _: &mut BbsinkState) -> PgResult<()> {
        Ok(())
    }
    fn begin_manifest(&mut self, _: &mut Bbsink<'a>, _: &mut BbsinkState) -> PgResult<()> {
        Ok(())
    }
    fn manifest_contents(
        &mut self,
        sink: &mut Bbsink<'a>,
        _: &mut BbsinkState,
        len: usize,
    ) -> PgResult<()> {
        append(
            &mut self.data.borrow_mut().manifest,
            sink.buffer_slice(len),
            64 * 1024 * 1024,
        )
    }
    fn end_manifest(&mut self, _: &mut Bbsink<'a>, _: &mut BbsinkState) -> PgResult<()> {
        Ok(())
    }
    fn end_backup(
        &mut self,
        _: &mut Bbsink<'a>,
        _: &mut BbsinkState,
        end: u64,
        tli: u32,
    ) -> PgResult<()> {
        let mut data = self.data.borrow_mut();
        if tli != data.timeline || end <= data.start {
            return Err(pg_error("invalid native backup boundary"));
        }
        data.end = end;
        Ok(())
    }
    fn cleanup(&mut self, _: &mut Bbsink<'a>, _: &mut BbsinkState) -> PgResult<()> {
        Ok(())
    }
}

pub(crate) fn capture(previous: Option<&[u8]>) -> Result<Capture> {
    let cx = mcx::MemoryContext::new("object backup");
    let shared = Rc::new(RefCell::new(Capture::default()));
    let sink = Box::new(Bbsink::new(
        cx.mcx(),
        Box::new(Collector {
            mcx: cx.mcx(),
            data: shared.clone(),
        }),
        None,
    ));
    walsender_seams::export_base_backup::call(cx.mcx(), sink, previous)?;
    Ok(Rc::try_unwrap(shared)
        .map_err(|_| "backup sink retained its capture")?
        .into_inner())
}

pub fn publish(store: &Store, data: PathBuf) -> Result<archive::Restored> {
    let capture = capture(None)?;
    let image = crate::image::export(store, &capture, None)?;
    let image_key = image.save(store)?;
    let Capture {
        start,
        end: backup_end,
        timeline,
        ..
    } = capture;
    let system = transam_xlog::GetSystemIdentifier();
    let segment = transam_xlog::wal_segment_size() as usize;
    let base = start - start % segment as u64;
    // Backup stop can leave the insertion cursor past an uninitialized page
    // header. Flush the actual backup-end record, not that cursor.
    transam_xlog::XLogFlush(backup_end)?;
    let mut tli = 0;
    let available = transam_xlog::GetFlushRecPtr(Some(&mut tli));
    if tli != timeline || available <= base || available - base > 64 * 1024 * 1024 {
        return Err("initial WAL exceeds publication bounds".into());
    }
    let mut bytes = vec![0; (available - base) as usize];
    if !xlogutils::memory_wal::read(tli, base, &mut bytes) {
        return Err("missing initial backup WAL".into());
    }
    let (record, end) = decode::last_record(&bytes, base, available, base, system, tli, segment)?;
    if end < backup_end {
        return Err("initial WAL does not cover backup completion".into());
    }
    bytes.truncate((end - base) as usize);
    let chunk = store.immutable("chunks", &bytes)?;
    let tail = store.immutable("descriptors", &serde_json::to_vec(&json!({"cluster":system.to_string(),"timeline":tli,"start":base,"end":end,"record_start":record,"previous":null,"chunk":chunk}))?)?;
    let info = json!({"version":2,"cluster":system.to_string(),"timeline":tli,"start":start,"end":backup_end,"manifest":digest(&image.manifest()),"anchor":tail,"archive_start":base,"seed_end":end,"seed_record_start":record,"root_history":null,"image":image_key});
    let backup = store.immutable("backups", &serde_json::to_vec(&info)?)?;
    let head = json!({"version":2,"cluster":system.to_string(),"timeline":tli,"start":base,"end":end,"record_start":record,"tail":tail,"backup":backup,"epoch":fresh()?,"revision":fresh()?});
    // This is the only mutable publication. A competing creator is never adopted.
    let snapshot = store.conditional("head", &serde_json::to_vec(&head)?, None)?;
    xlogutils::memory_wal::advance_archive_floor(base);
    Ok(archive::Restored {
        snapshot,
        head,
        root_history: Vec::new(),
        chunks: 1,
        system,
        segment,
        segments: BTreeMap::new(),
        data,
    })
}
