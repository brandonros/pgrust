#!/usr/bin/env bash
#
# The single-writer lease, with two servers on one bucket. B is refused while
# A renews; when A dies B takes over at once (same host, pid gone); a paused A
# that comes back after its lease expired is fenced on its next write.
#
# The pause step waits out the lease TTL (30 s), so this script takes ~1 min.
#
. "$(dirname "$0")/server.sh"

PORT2=$((PORT + 1))
SOCKDIR2="$WORK/sock2"
PGDATA2="$WORK/pgdata2"
LOG2="$WORK/server2.log"
B_PID=""

psqlb() { psql -h "$SOCKDIR2" -p "$PORT2" -X -d postgres -tAc "$1" 2>&1; }
boot_b() {
    mkdir -p "$SOCKDIR2"
    "$BIN" -D "$PGDATA2" -k "$SOCKDIR2" -p "$PORT2" -c listen_addresses='' -c autovacuum=off &>"$LOG2" &
    B_PID=$!
    OBJKV_PIDS="$OBJKV_PIDS $B_PID"   # so the EXIT trap stops it too
    local i
    for i in $(seq 1 360); do
        psqlb "SELECT 1" >/dev/null 2>&1 && return 0
        kill -0 "$B_PID" 2>/dev/null || die "server B exited during startup" "$(tail -20 "$LOG2")"
        sleep 0.25
    done
    die "server B did not accept connections within 90s"
}

fresh_cluster
A_PID="${OBJKV_PIDS##* }"
sql "CREATE TABLE t (id int PRIMARY KEY, v text COLLATE \"C\") USING objkv; INSERT INTO t VALUES (1, 'from A');" >/dev/null
check "A owns the bucket and writes" "1" "$(sql "SELECT count(*) FROM t;")"

echo "1. a second server on the same bucket is refused while A renews"
rm -rf "$PGDATA2"
initdb -D "$PGDATA2" -U "$(id -un)" >"$WORK/initdb2.log" 2>&1 || die "initdb for B failed"
boot_b
psqlb "CREATE ACCESS METHOD objkv TYPE TABLE HANDLER heap_tableam_handler;" >/dev/null 2>&1
psqlb "CREATE ACCESS METHOD objkv_btree TYPE INDEX HANDLER bthandler;" >/dev/null 2>&1
OUT=$(psqlb "CREATE TABLE u (id int PRIMARY KEY) USING objkv; INSERT INTO u VALUES (1);")
contains "B is refused, naming the owner" "this bucket is owned by" "$OUT"
contains "and told it is A's pid" ":$A_PID (lease epoch" "$OUT"
check "A is unaffected" "1" "$(sql "SELECT count(*) FROM t;")"

echo "2. A is killed; B takes over at once, without waiting out the TTL"
kill -9 "$A_PID"; wait "$A_PID" 2>/dev/null || true
OBJKV_PIDS="$B_PID"
START=$(date +%s)
OUT=$(psqlb "CREATE TABLE u (id int PRIMARY KEY) USING objkv; INSERT INTO u VALUES (1);" | tail -1)
check "B's write succeeds" "INSERT 0 1" "$OUT"
TOOK=$(( $(date +%s) - START ))
[ "$TOOK" -lt 15 ] && ok "takeover took ${TOOK}s (no TTL wait)" || fail "takeover took ${TOOK}s; expected the dead-pid fast path"
# A and B have separate local catalogs (no lift), so B does not know table t;
# what they share is the bucket and its lease.
check "B reads its own row back" "1" "$(psqlb "SELECT count(*) FROM u;")"

echo "3. a writer that stops renewing is taken over after the TTL, and fenced when it returns"
# B is now the owner. Pause it past the TTL, boot A again on its old directory,
# let A take over, then resume B: B's next write must be refused.
kill -STOP "$B_PID"
sleep 33
boot   # A, on $PGDATA, port $PORT
OBJKV_PIDS="$OBJKV_PIDS $B_PID"
START=$(date +%s)
OUT=$(sql "INSERT INTO t VALUES (2, 'A again');" | tail -1)
check "A takes over the expired lease" "INSERT 0 1" "$OUT"
kill -CONT "$B_PID"
sleep 2
OUT=$(psqlb "INSERT INTO u VALUES (2);")
# Either wording is a fence: the heartbeat noticed the expiry, or the PUT
# path saw a higher epoch. Both refuse the write and tell the operator.
contains "B, resumed, is fenced on its next write" "can no longer write to the bucket" "$OUT"
check "A's write landed" "2" "$(sql "SELECT count(*) FROM t;")"

echo "4. a clean shutdown releases the lease; the next boot claims at once"
stop TERM
START=$(date +%s)
boot
OUT=$(sql "INSERT INTO t VALUES (3, 'after restart');" | tail -1)
check "write after a clean restart" "INSERT 0 1" "$OUT"
TOOK=$(( $(date +%s) - START ))
[ "$TOOK" -lt 15 ] && ok "restart took ${TOOK}s" || fail "restart took ${TOOK}s; the lease was not released"

finish "the single-writer lease"
