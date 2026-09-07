//! PostgreSQL native incremental selection, using existing WAL summaries.
use crate::incremental_manifest::{error, Uploaded, WalRange};
use blkreftable::{BlockRefTable, BlockRefTableReader};
use mcx::Mcx;
use std::rc::Rc;
use types_core::ForkNumber;
use types_error::PgResult;
use types_storage::RelFileLocator;

pub const RELSEG_SIZE: u32 = (1024 * 1024 * 1024) / types_core::BLCKSZ as u32;
pub const MAGIC: u32 = 0xd3ae1f0d;
pub struct FilePlan {
    pub blocks: Vec<u32>,
    pub truncation: u32,
}
impl FilePlan {
    pub fn header_size(&self) -> usize {
        let size = 12 + self.blocks.len() * 4;
        if self.blocks.is_empty() {
            size
        } else {
            size.div_ceil(types_core::BLCKSZ) * types_core::BLCKSZ
        }
    }
    pub fn size(&self) -> i64 {
        (self.header_size() + self.blocks.len() * types_core::BLCKSZ) as i64
    }
    pub fn header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_size());
        for word in [MAGIC, self.blocks.len() as u32, self.truncation]
            .into_iter()
            .chain(self.blocks.iter().copied())
        {
            out.extend_from_slice(&word.to_ne_bytes());
        }
        out.resize(self.header_size(), 0);
        out
    }
}
pub struct Prepared<'m> {
    reference: Rc<Uploaded>,
    table: BlockRefTable<'m>,
}

// Return summary intervals required by the ancestor backup, oldest first.
fn required_ranges(
    prior: &[WalRange],
    history: &[timeline::TimeLineHistoryEntry],
    start: u64,
) -> PgResult<Vec<WalRange>> {
    let mut positions = Vec::new();
    for range in prior {
        let i = history
            .iter()
            .position(|h| h.tli == range.tli)
            .ok_or_else(|| error("manifest timeline is not in server history"))?;
        positions.push(i);
    }
    let first = *positions
        .iter()
        .max()
        .ok_or_else(|| error("manifest contains no WAL ranges"))?;
    let last = *positions.iter().min().unwrap();
    let origin = prior
        .iter()
        .find(|r| r.tli == history[first].tli)
        .unwrap()
        .start;
    if positions.len() != first - last + 1 {
        return Err(error("manifest timeline ranges are discontinuous"));
    }
    for (range, i) in prior.iter().zip(positions) {
        let h = history[i];
        if (i == first && range.start < h.begin)
            || (i != first && range.start != h.begin)
            || (i != last && range.end != h.end)
            || range.end > start
            || (h.end != 0 && range.end > h.end)
        {
            return Err(error("manifest WAL bounds do not match server history"));
        }
    }
    if origin >= start {
        return Err(error("incremental backup requires a later checkpoint"));
    }
    Ok((0..=first)
        .rev()
        .filter_map(|i| {
            let h = history[i];
            let begin = if i == first { origin } else { h.begin };
            let end = if i == 0 { start } else { h.end };
            (begin < end).then_some(WalRange {
                tli: h.tli,
                start: begin,
                end,
            })
        })
        .collect())
}
fn check_coverage(range: &WalRange, summaries: &[(u64, u64)]) -> PgResult<()> {
    let mut cursor = range.start;
    for &(start, end) in summaries {
        if start > cursor {
            break;
        }
        cursor = cursor.max(end);
        if cursor >= range.end {
            return Ok(());
        }
    }
    Err(error(format!(
        "WAL summaries are incomplete on timeline {} at {:X}/{:X}",
        range.tli,
        cursor >> 32,
        cursor as u32
    )))
}
impl<'m> Prepared<'m> {
    pub fn new(
        mcx: Mcx<'m>,
        reference: Rc<Uploaded>,
        state: &mut xlogbackup::BackupState,
    ) -> PgResult<Self> {
        let history =
            timeline::readTimeLineHistory(mcx, state.starttli, state.started_in_recovery)?;
        let ranges = required_ranges(&reference.ranges, &history, state.startpoint)?;
        let first = ranges
            .first()
            .ok_or_else(|| error("empty incremental range"))?;
        state.istartpoint = first.start;
        state.istarttli = first.tli;
        walsummarizer::WaitForWalSummarization(state.startpoint)?;
        let mut table = BlockRefTable::new(mcx);
        for range in ranges {
            let mut files = walsummarizer::GetWalSummaries(mcx, range.tli, range.start, range.end)?;
            files.sort_by_key(|s| (s.start_lsn, s.end_lsn));
            check_coverage(
                &range,
                &files
                    .iter()
                    .map(|s| (s.start_lsn, s.end_lsn))
                    .collect::<Vec<_>>(),
            )?;
            for file in files {
                postgres_seams::check_for_interrupts::call()?;
                let path = format!(
                    "pg_wal/summaries/{:08X}{:08X}{:08X}{:08X}{:08X}.summary",
                    file.tli,
                    file.start_lsn >> 32,
                    file.start_lsn as u32,
                    file.end_lsn >> 32,
                    file.end_lsn as u32
                );
                let fd = fd::OpenTransientFile(&path, libc::O_RDONLY)?;
                if fd < 0 {
                    return Err(error(format!("could not open required WAL summary {path}")));
                }
                let mut offset = 0;
                let result: PgResult<()> = (|| {
                    let mut reader = BlockRefTableReader::new(
                        mcx,
                        |out| {
                            let n = fd::pg_pread(fd, out, offset);
                            if n < 0 {
                                return Err(error("could not read WAL summary"));
                            }
                            offset += n as i64;
                            Ok(n as usize)
                        },
                        &path,
                    )?;
                    while let Some((locator, fork, limit)) = reader.next_relation()? {
                        table.set_limit_block(locator, fork, limit);
                        let mut blocks = [0; 512];
                        loop {
                            let n = reader.get_blocks(&mut blocks)?;
                            if n == 0 {
                                break;
                            }
                            for block in &blocks[..n] {
                                table.mark_block_modified(locator, fork, *block)?;
                            }
                            postgres_seams::check_for_interrupts::call()?;
                        }
                    }
                    Ok(())
                })();
                fd::CloseTransientFile(fd);
                result?;
            }
        }
        Ok(Self { reference, table })
    }
    pub fn select(
        &self,
        path: &str,
        locator: RelFileLocator,
        fork: ForkNumber,
        seg: u32,
        size: i64,
    ) -> PgResult<Option<FilePlan>> {
        let page = types_core::BLCKSZ as i64;
        if size <= 0
            || size % page != 0
            || size / page > RELSEG_SIZE as i64
            || fork == ForkNumber::FSM_FORKNUM
        {
            return Ok(None);
        }
        let (dir, name) = path
            .rsplit_once('/')
            .ok_or_else(|| error("invalid relation backup path"))?;
        let ipath = format!("{dir}/INCREMENTAL.{name}");
        if !self.reference.files.contains_key(path.as_bytes())
            && !self.reference.files.contains_key(ipath.as_bytes())
        {
            return Ok(None);
        }
        let db = RelFileLocator {
            relNumber: 0,
            ..locator
        };
        if self.table.get_entry(db, ForkNumber::MAIN_FORKNUM).is_some() {
            return Ok(None);
        }
        let entry = self.table.get_entry(locator, fork);
        let count = (size / page) as u32;
        let Some(entry) = entry else {
            return Ok(Some(FilePlan {
                blocks: Vec::new(),
                truncation: count,
            }));
        };
        let start = seg
            .checked_mul(RELSEG_SIZE)
            .ok_or_else(|| error("relation segment overflow"))?;
        let stop = start
            .checked_add(count)
            .ok_or_else(|| error("relation block overflow"))?;
        let limit = entry.limit_block();
        if limit <= start {
            return Ok(None);
        }
        let mut blocks = vec![0; count as usize];
        let n = entry.get_blocks(start, stop, &mut blocks);
        blocks.truncate(n);
        if n as u64 * 10 > count as u64 * 9 {
            return Ok(None);
        }
        blocks.sort_unstable();
        for b in &mut blocks {
            *b -= start;
        }
        // Native truncation boundary: predecessor blocks may be reused below
        // this length; current blocks above it determine the reconstructed tail.
        let truncation = if limit == u32::MAX {
            count
        } else {
            count.max(limit - start).min(RELSEG_SIZE)
        };
        Ok(Some(FilePlan { blocks, truncation }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn coverage_rejects_gaps_accepts_overlap() {
        let r = WalRange {
            tli: 1,
            start: 100,
            end: 300,
        };
        for s in [
            vec![],
            vec![(0, 90), (100, 200)],
            vec![(100, 200), (201, 400)],
            vec![(101, 300)],
        ] {
            assert!(check_coverage(&r, &s).is_err());
        }
        check_coverage(&r, &[(0, 150), (120, 220), (220, 400)]).unwrap();
    }
    #[test]
    fn ancestry_uses_prior_start_across_timelines() {
        use timeline::TimeLineHistoryEntry as H;
        let history = [
            H {
                tli: 3,
                begin: 300,
                end: 0,
            },
            H {
                tli: 2,
                begin: 200,
                end: 300,
            },
            H {
                tli: 1,
                begin: 0,
                end: 200,
            },
        ];
        let r = WalRange {
            tli: 1,
            start: 100,
            end: 150,
        };
        assert_eq!(
            required_ranges(&[r.clone()], &history, 400).unwrap(),
            vec![
                WalRange {
                    tli: 1,
                    start: 100,
                    end: 200
                },
                WalRange {
                    tli: 2,
                    start: 200,
                    end: 300
                },
                WalRange {
                    tli: 3,
                    start: 300,
                    end: 400
                }
            ]
        );
        assert!(required_ranges(
            &[WalRange {
                tli: 9,
                ..r.clone()
            }],
            &history,
            400
        )
        .is_err());
        assert!(required_ranges(
            &[WalRange {
                end: 201,
                ..r.clone()
            }],
            &history,
            400
        )
        .is_err());
        assert!(required_ranges(
            &[WalRange {
                tli: 2,
                start: 199,
                end: 220
            }],
            &history,
            400
        )
        .is_err());
        assert!(required_ranges(
            &[
                r,
                WalRange {
                    tli: 3,
                    start: 300,
                    end: 350
                }
            ],
            &history,
            400
        )
        .is_err());
    }
    #[test]
    fn selection_sparse_segment_truncation_and_creation() {
        let cx = mcx::MemoryContext::new("incremental selection test");
        let locator = RelFileLocator {
            spcOid: 1663,
            dbOid: 5,
            relNumber: 10,
        };
        let fork = ForkNumber::MAIN_FORKNUM;
        let mut p = Prepared {
            reference: Rc::new(Uploaded {
                files: BTreeMap::from([
                    (b"base/5/10".to_vec(), 819200),
                    (b"base/5/INCREMENTAL.10.1".to_vec(), 12),
                ]),
                ranges: vec![],
            }),
            table: BlockRefTable::new(cx.mcx()),
        };
        assert!(p
            .select("base/5/11", locator, fork, 0, 819200)
            .unwrap()
            .is_none());
        let unchanged = p
            .select("base/5/10", locator, fork, 0, 819200)
            .unwrap()
            .unwrap();
        assert!(unchanged.blocks.is_empty());
        assert_eq!(unchanged.size(), 12);
        assert_eq!(unchanged.truncation, 100);
        p.table.mark_block_modified(locator, fork, 4).unwrap();
        p.table.mark_block_modified(locator, fork, 1).unwrap();
        let changed = p
            .select("base/5/10", locator, fork, 0, 819200)
            .unwrap()
            .unwrap();
        assert_eq!(changed.blocks, vec![1, 4]);
        assert_eq!(changed.size(), 3 * 8192);
        assert_eq!(
            &changed.header()[..12],
            [
                MAGIC.to_ne_bytes(),
                2u32.to_ne_bytes(),
                100u32.to_ne_bytes()
            ]
            .concat()
        );
        p.table
            .mark_block_modified(locator, fork, RELSEG_SIZE + 7)
            .unwrap();
        assert_eq!(
            p.select("base/5/10.1", locator, fork, 1, 819200)
                .unwrap()
                .unwrap()
                .blocks,
            vec![7]
        );
        assert!(p
            .select("base/5/10", locator, ForkNumber::FSM_FORKNUM, 0, 819200)
            .unwrap()
            .is_none());
        p.table.set_limit_block(locator, fork, 0);
        assert!(p
            .select("base/5/10", locator, fork, 0, 819200)
            .unwrap()
            .is_none());
        // A database-level creation entry also forces complete copies.
        let mut p = Prepared {
            table: BlockRefTable::new(cx.mcx()),
            ..p
        };
        p.table.set_limit_block(
            RelFileLocator {
                relNumber: 0,
                ..locator
            },
            fork,
            0,
        );
        assert!(p
            .select("base/5/10", locator, fork, 0, 819200)
            .unwrap()
            .is_none());
    }
}
