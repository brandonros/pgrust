# objkv: Postgres tables in an object store

objkv is an opt-in table and index access method that keeps rows as
key/value entries whose durable form is immutable objects in an S3-compatible
store. Each transaction is one object; the object landing is the commit.
Local disk is a cache. The system catalogs can be moved into the bucket too
(the "lift"), after which a blank machine can boot against the bucket.

This document is the contract. Anything not listed under "What works" is
unsupported, and unsupported operations raise a named error rather than doing
something quietly different.

## Enabling it

- Set `OBJKV_S3_ENDPOINT`, `OBJKV_S3_BUCKET`, `OBJKV_S3_KEY`, `OBJKV_S3_SECRET`.
  If the endpoint is unset the server refuses to open objkv storage. There is
  no memory mode; the in-memory store in the engine crate is a test double.
  The store is logged at open.
- `CREATE TABLE ... USING objkv`. Indexes on objkv tables use `objkv_btree`.

## Isolation contract (differs from PostgreSQL)

objkv tables provide snapshot isolation with first-committer-wins validation.
This is not PostgreSQL's locking model, and the differences are deliberate:

| Situation | PostgreSQL (heap) | objkv |
|---|---|---|
| Two transactions update the same row | second blocks until the first commits, then re-evaluates (READ COMMITTED) or fails with 40001 (REPEATABLE READ) | neither blocks; the second to commit fails with 40001 `serialization_failure`, at any isolation level |
| Two sessions insert the same unique key | second blocks, then 23505 `unique_violation` | second to commit fails with 40001 |
| Concurrent `INSERT ... ON CONFLICT DO NOTHING/UPDATE` | serialised by the index lock; both succeed | the loser fails with 40001 and must retry |
| `READ COMMITTED` | each statement sees a fresh snapshot | behaves as REPEATABLE READ: one snapshot for the transaction; conflicts are validated against it |
| `SELECT ... FOR UPDATE / FOR SHARE / FOR KEY SHARE` | row lock | 0A000 `feature_not_supported`. Foreign keys that reference an objkv table therefore fail loudly. |
| Row locks, advisory of tuple state (`xmin`, `xmax`, `ctid` stability) | available | `xmin`/`xmax` are not meaningful; `tableoid` is set; TIDs are synthetic and stable within a transaction |

Applications must be prepared to retry on 40001.

## Single writer

One server writes a bucket at a time. Ownership is a lease object with a
30 s expiry (`objkv::lease::TTL_MS`), renewed every 10 s by a heartbeat
thread using a conditional write. A second server on the same bucket is
refused while the lease is live, naming the owner. After a crash the lease
expires and any host may take over; the takeover bumps an epoch that is
stamped into every commit object, so a resumed stale writer's later objects
are ignored and its next PUT is refused. Clean shutdown releases the lease.

## Time travel

`SET pgrust.objkv_snapshot_seq = N` (superuser only) reads the database as
of commit N. While it is set, writes to objkv tables are refused
(`cannot write objkv tables while reading a past snapshot`). The forced
snapshot is registered as in use, so the collector cannot pass it. Reading
below the collection horizon is refused rather than guessed.

## Indexes

- Supported: equality, ranges, prefix `LIKE`, `IS [NOT] NULL`, `IN` lists,
  bitmap AND/OR, index-only scans, ordered scans in both directions, partial
  and expression indexes, `DESC`, `NULLS FIRST/LAST`, multi-column keys,
  cross-width integer comparisons (`bigint_col = 42`).
- Text, varchar and char(n) columns must use `COLLATE "C"`; any other
  collation is refused at `CREATE INDEX` and at insert. `char(n)` compares
  blank-trimmed, as in PostgreSQL.
- A scan cannot change direction mid-way (cursor `FETCH BACKWARD` after
  `FORWARD` errors).
- Index rows are limited to 400 encoded bytes.

## Storage limits

- No TOAST table. Values are flattened (detoasted and decompressed) before
  storage; a row that exceeds the objkv row limit fails with 54000
  `program_limit_exceeded`.
- Not supported and refused: temp and unlogged objkv tables, `TABLESAMPLE`,
  parallel scans, `CLUSTER`, `VACUUM FULL`, `ALTER TABLE` rewrites,
  `SET ACCESS METHOD`.
- `VACUUM` is a no-op on objkv tables (the compactor and collector run on
  their own threads). `ANALYZE` works.

## The lift and blank-machine restore

`objkv_lift_verify()` / `objkv_lift()` (superuser) move the system catalogs
into the bucket. The lift refuses, naming the offenders, when the cluster
has any user relation that is not already objkv (heap tables, their indexes,
materialized views), any sequence (so `serial` and identity columns are
unsupported on a lifted cluster), or any objkv row carrying an external
TOAST pointer. After the lift, `CREATE DATABASE` is refused.

To restore on a blank machine: `initdb` a fresh data directory, restore the
objkv marker file, set the S3 variables, start. Static credentials only;
there is no credentials provider.

## Durability model

- A transaction's object is written at pre-commit. Once it lands it is a
  commit, even if the client never received the acknowledgement.
- An abort after the object landed is recorded by a discard marker carrying
  the xid and object hash; a marker that cannot be written is fatal.
- Group commit keeps up to eight objects in flight and acknowledges in
  sequence. A PUT whose response was lost is re-read from the store before
  it is treated as failed.
- `pgrust.objkv_async_queue` enables asynchronous commit with a bounded
  queue; a crash loses at most the queued commits.
- Old versions stay readable until `pgrust.objkv_retain_commits` commits
  have been folded and collected.
