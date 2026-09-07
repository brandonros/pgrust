use crate::Result;
use types_core::{TimeLineID, XLogRecPtr, XLogSegNo};
use types_error::PgResult;
use xlogreader::{XLogReaderRoutine, XLogReaderState, XLogSegmentRoutine};
use xlogreader_seams::XLogReaderState as ReaderView;
struct Input<'a> {
    bytes: &'a [u8],
    base: u64,
    end: u64,
    timeline: u32,
}
impl XLogSegmentRoutine for Input<'_> {
    fn segment_open(
        &mut self,
        _: &mut ReaderView,
        _: XLogSegNo,
        _: &mut TimeLineID,
    ) -> PgResult<()> {
        unreachable!("flat memory input")
    }
    fn segment_close(&mut self, _: &mut ReaderView) {}
}
impl XLogReaderRoutine for Input<'_> {
    fn page_read(
        &mut self,
        v: &mut ReaderView,
        page: XLogRecPtr,
        required: i32,
        _: XLogRecPtr,
        buffer: &mut [u8],
    ) -> PgResult<i32> {
        if required < 0
            || page < self.base
            || page >= self.end
            || page
                .checked_add(required as u64)
                .is_none_or(|p| p > self.end)
        {
            return Ok(-1);
        }
        let count = buffer.len().min((self.end - page) as usize);
        let offset = (page - self.base) as usize;
        buffer[..count].copy_from_slice(&self.bytes[offset..offset + count]);
        v.seg.ws_tli = self.timeline;
        Ok(count as i32)
    }
}
pub fn last_record(
    bytes: &[u8],
    base: u64,
    end: u64,
    start: u64,
    system: u64,
    timeline: u32,
    segment: usize,
) -> Result<(u64, u64)> {
    read_records(bytes, base, end, start, system, timeline, segment, false)
}

pub fn first_record(
    bytes: &[u8],
    base: u64,
    start: u64,
    system: u64,
    timeline: u32,
    segment: usize,
) -> Result<(u64, u64)> {
    read_records(
        bytes,
        base,
        base + bytes.len() as u64,
        start,
        system,
        timeline,
        segment,
        true,
    )
}

fn read_records(
    bytes: &[u8],
    base: u64,
    end: u64,
    start: u64,
    system: u64,
    timeline: u32,
    segment: usize,
    first_only: bool,
) -> Result<(u64, u64)> {
    if end < base
        || end - base != bytes.len() as u64
        || base > start
        || start > end
        || base % segment as u64 != 0
    {
        return Err("invalid native WAL input bounds".into());
    }
    let cx = mcx::MemoryContext::new("object WAL record validation");
    let mut reader = XLogReaderState::allocate(cx.mcx(), segment as i32)?;
    reader.system_identifier = system;
    reader.v.seg.ws_tli = timeline;
    let mut input = Input {
        bytes,
        base,
        end,
        timeline,
    };
    if start == base {
        reader.XLogFindNextRecord(&mut input, start)?;
    } else {
        reader.XLogBeginRead(start);
    }
    let mut last = (0, 0);
    if reader.errormsg().is_none() && reader.v.EndRecPtr != 0 {
        while reader.XLogReadRecord(&mut input)?.is_some() {
            if reader.v.EndRecPtr > end {
                break;
            }
            last = (reader.v.ReadRecPtr, reader.v.EndRecPtr);
            if first_only {
                break;
            }
        }
    }
    if let Some(error) = reader.errormsg() {
        return Err(format!("native WAL validation failed: {error}").into());
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use manifest::{PgChecksumContext, PgChecksumType};

    #[test]
    fn partial_flush_does_not_advance_past_a_complete_record() {
        const SEGMENT: usize = 1024 * 1024;
        let base = SEGMENT as u64;
        let mut bytes = vec![0u8; 88];
        bytes[..2].copy_from_slice(&xlogreader::XLOG_PAGE_MAGIC.to_ne_bytes());
        bytes[2..4].copy_from_slice(&2u16.to_ne_bytes()); // Long page header.
        bytes[4..8].copy_from_slice(&1u32.to_ne_bytes());
        bytes[8..16].copy_from_slice(&base.to_ne_bytes());
        bytes[24..32].copy_from_slice(&42u64.to_ne_bytes());
        bytes[32..36].copy_from_slice(&(SEGMENT as u32).to_ne_bytes());
        bytes[36..40].copy_from_slice(&8192u32.to_ne_bytes());
        for offset in [40, 64] {
            bytes[offset..offset + 4].copy_from_slice(&24u32.to_ne_bytes());
            let previous = if offset == 40 { 0 } else { base + 40 };
            bytes[offset + 8..offset + 16].copy_from_slice(&previous.to_ne_bytes());
            bytes[offset + 16] = 0x20; // XLOG_NOOP, no payload.
            let mut crc = PgChecksumContext::init(PgChecksumType::Crc32c);
            crc.update(&bytes[offset..offset + 20]);
            crc.finalize(&mut bytes[offset + 20..offset + 24]);
        }
        let read = |data: &[u8], start| {
            last_record(data, base, base + data.len() as u64, start, 42, 1, SEGMENT)
        };
        assert_eq!(read(&bytes[..80], base).unwrap(), (base + 40, base + 64));
        assert_eq!(read(&bytes[..80], base + 64).unwrap(), (0, 0));
        assert_eq!(read(&bytes, base + 64).unwrap(), (base + 64, base + 88));
        bytes[84] ^= 1;
        assert!(read(&bytes, base + 64).is_err());
    }
}
