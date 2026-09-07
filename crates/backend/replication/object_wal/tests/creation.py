"""Native creation integration test against local MinIO.
Build: cargo build --offline -p main_main --bin postgres
Only initdb and SQL clients are used: no prebuilt backup/archive fixture.
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--startup-faults', action='store_true')
    parser.add_argument('--crashes', type=int, default=0)
    parser.add_argument('--renewals', type=int, default=0)
    parser.add_argument('--server', default='target/debug/postgres')
    parser.add_argument('--pg-bin', required=True)
    parser.add_argument('--sharedir', required=True)
    parser.add_argument('--endpoint', default='http://127.0.0.1:9000')
    parser.add_argument('--bucket', default='pgrust-wal-experiments')
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix='native-create-', dir='/tmp'))
    print(root, flush=True)
    prefix = 'create-' + uuid.uuid4().hex + '/'
    pg = Path(args.pg_bin)
    server = Path(args.server).resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    env.update(AWS_ACCESS_KEY_ID='minioadmin', AWS_SECRET_ACCESS_KEY='minioadmin',
               AWS_DEFAULT_REGION='us-east-1', PGRUST_PGSHAREDIR=args.sharedir,
               PGRUST_TZDIR='/usr/share/zoneinfo', RUST_MIN_STACK='33554432', PGCONNECT_TIMEOUT='2')
    env.pop('AWS_SESSION_TOKEN', None)
    processes = []

    def run(command, **kw):
        return subprocess.run(list(map(str, command)), env=env, check=True, capture_output=True,
                              text=True, timeout=kw.pop('timeout', 120), **kw).stdout.strip()

    def head():
        dest = root / 'head'
        try:
            run(['aws', '--endpoint-url', args.endpoint, 's3api', 'get-object', '--bucket', args.bucket,
                 '--key', prefix + 'head', dest])
        except subprocess.CalledProcessError as error:
            assert 'NoSuchKey' in error.stderr, error.stderr
            return None
        return dest.read_bytes()

    def get_json(key):
        dest = root / 'inspect-object'
        run(['aws', '--endpoint-url', args.endpoint, 's3api', 'get-object', '--bucket', args.bucket, '--key', prefix+key, dest])
        return json.loads(dest.read_bytes())

    def inventory():
        value = json.loads(run(['aws', '--endpoint-url', args.endpoint, 's3api', 'list-objects-v2', '--bucket', args.bucket, '--prefix', prefix]))
        return {o['Key'][len(prefix):]:o['Size'] for o in value.get('Contents', [])}

    def owned(key):
        parts = key.split('/')
        return len(parts)==2 and parts[0] in ('chunks','descriptors','backups','backup-chunks','snapshot-index','retired','histories') and len(parts[1])==64 and all(c in '0123456789abcdef' for c in parts[1])

    def reachable(h):
        live = set()
        def read(kind, key):
            name = kind+'/'+key
            live.add(name)
            return get_json(name)
        tail = h['tail']
        while tail:
            node = read('descriptors', tail)
            live.add('chunks/'+node['chunk'])
            tail = node['previous']
        info = read('backups', h['backup'])
        if info.get('root_history'):
            live.add('histories/'+info['root_history'])
        node = h
        while node.get('transition'):
            live.add('histories/'+node['transition']['history'])
            node = node['transition']['parent']
        image = read('snapshot-index', info['image'])
        for pieces in image['files'].values():
            live.update('backup-chunks/'+p['key'] for p in pieces)
        if h.get('garbage'):
            live.add('retired/'+h['garbage'])
        return live

    def sql(sock, query):
        return run([pg / 'psql', '-XAt', '-h', sock, '-p', '55441', '-U', 'postgres',
                    '-d', 'postgres', '-c', query], timeout=20)

    endpoint = urllib.parse.urlsplit(args.endpoint)
    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Signed URLs must not be logged.

        def do_GET(self):
            self.exchange()

        def do_PUT(self):
            self.exchange()

        def do_DELETE(self):
            self.exchange()

        def exchange(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            path = self.path.split('?', 1)[0]
            if self.command == 'PUT' and '/backup-chunks/' in path and proxy.fail.is_set():
                proxy.failed_uploads += 1
                self.send_response(503)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            if self.command == 'PUT' and '/backup-chunks/' in path and proxy.pause_snapshot.is_set():
                proxy.snapshot_pending.set()
                if not proxy.snapshot_release.wait(4):
                    self.send_response(503)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
            if self.command == 'DELETE' and proxy.delete_generation is not None and proxy.latest_generation >= proxy.delete_generation:
                proxy.delete_pending.set()
                if not proxy.delete_release.wait(4):
                    self.send_response(503)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
            is_head = self.command == 'PUT' and path.endswith('/head')
            renewal_head = is_head and json.loads(body).get('generation', 0) > 0
            if is_head and proxy.block.is_set():
                with proxy.condition:
                    proxy.pending.add(hashlib.sha256(body).digest())
                    proxy.condition.notify_all()
                if not proxy.release.wait(4):
                    self.send_response(503)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
            connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port or 80, timeout=10)
            try:
                connection.request(self.command, self.path, body=body, headers=dict(self.headers))
                response = connection.getresponse()
                data = response.read()
                if self.command == 'GET' and 'list-type=2' in self.path and proxy.race_listing.is_set():
                    with proxy.condition:
                        proxy.list_readers += 1
                        if proxy.list_readers == 2:
                            proxy.list_release.set()
                    assert proxy.list_release.wait(4), 'creators did not inspect the empty prefix together'
                phase = ('delete' if self.command == 'DELETE' else
                         'payload' if '/backup-chunks/' in path else
                         'index' if '/snapshot-index/' in path else
                         'metadata' if '/backups/' in path else
                         'head' if is_head and json.loads(body).get('generation', 0) > proxy.fault_generation else
                         '')
                if response.status in (200, 204) and self.command in ('PUT', 'DELETE') and phase == proxy.fault_phase:
                    proxy.fault_phase = None
                    proxy.fault_hit.set()
                    proxy.fault_release.wait(4)
                    self.close_connection = True
                    return
                if is_head and response.status == 200:
                    proxy.latest_generation = json.loads(body).get('generation', 0)
                if self.command == 'PUT' and '/backup-chunks/' in path and response.status == 200:
                    with proxy.condition:
                        proxy.backup_bytes += len(body)
                if is_head and response.status == 200 and (proxy.drop.is_set() or (renewal_head and proxy.drop_renewal.is_set())):
                    proxy.drop.clear()
                    proxy.drop_renewal.clear()
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ('content-length', 'transfer-encoding', 'connection'):
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                connection.close()

    proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    proxy.race_listing = threading.Event()
    proxy.list_release = threading.Event()
    proxy.list_readers = 0
    proxy.fault_phase = None
    proxy.fault_generation = 0
    proxy.fault_hit = threading.Event()
    proxy.fault_release = threading.Event()
    proxy.failed_uploads = 0
    proxy.backup_bytes = 0
    proxy.latest_generation = 0
    proxy.delete_generation = None
    proxy.delete_pending = threading.Event()
    proxy.delete_release = threading.Event()
    proxy.pause_snapshot = threading.Event()
    proxy.snapshot_pending = threading.Event()
    proxy.snapshot_release = threading.Event()
    proxy.drop_renewal = threading.Event()
    proxy.fail = threading.Event()
    proxy.block = threading.Event()
    proxy.drop = threading.Event()
    proxy.release = threading.Event()
    proxy.condition = threading.Condition()
    proxy.pending = set()
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()

    def start(name, create, data=None, fenced=None):
        data = data or root / ('data-' + name)
        if create and not data.exists():
            run([pg / 'initdb', '-D', data, '-U', 'postgres', '-A', 'trust', '--no-locale',
                 '--encoding=UTF8', '--data-checksums'])
        config = root / ('config-' + name)
        config.mkdir()
        sock = root / ('socket-' + name)
        sock.mkdir()
        values = dict(data_directory=str(data), hba_file=str(config / 'pg_hba.conf'),
                      ident_file=str(config / 'pg_ident.conf'), listen_addresses='',
                      unix_socket_directories=str(sock), port='55441', io_method='sync',
                      shared_buffers='16MB', max_connections='16', max_stack_depth='6000',
                      wal_level='replica', fsync='on', synchronous_commit='on',
                      synchronous_standby_names='', hot_standby='off', restart_after_crash='off')
        values.update({'pgrust.s3': 'on', 'pgrust.s3_create': 'on' if create else 'off',
                       'pgrust.memory_wal': '256MB', 'pgrust.strict_synchronous_commit': 'on',
                       'pgrust.s3_endpoint': f'http://127.0.0.1:{proxy.server_port}',
                       'pgrust.s3_bucket': args.bucket, 'pgrust.s3_prefix': prefix})
        if not create:
            values['pgrust.s3_fenced_head'] = fenced or hashlib.sha256(head()).hexdigest()
        (config / 'postgresql.conf').write_text('\n'.join(k + "='" + v.replace("'", "''") + "'" for k, v in values.items()))
        (config / 'pg_hba.conf').write_text('local all all trust\nlocal replication all trust\n')
        (config / 'pg_ident.conf').touch()
        with (root / ('native-' + name + '.log')).open('w') as log:
            process = subprocess.Popen([str(server), '-D', str(config)], env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        return process, data, sock

    def ready(process, sock):
        deadline = time.monotonic() + 120
        while True:
            assert process.poll() is None, f'server exited; inspect logs in {root}'
            try:
                sql(sock, 'SELECT 1')
                return
            except subprocess.CalledProcessError:
                if time.monotonic() > deadline:
                    raise RuntimeError('SQL readiness timed out')
                time.sleep(.1)

    try:
        assert head() is None
        proxy.fail.set()
        failed, failed_data, failed_sock = start('failed-upload', True)
        assert failed.wait(timeout=90) != 0
        assert proxy.failed_uploads > 0, f'creation failed before reaching S3; inspect {root}'
        assert head() is None, 'failed upload published an authoritative head'
        try:
            sql(failed_sock, 'SELECT 1')
            raise AssertionError('failed creation admitted SQL')
        except subprocess.CalledProcessError:
            pass
        proxy.fail.clear()
        shutil.rmtree(failed_data)

        # A real partial initial upload has no authoritative head. Retrying
        # creation must refuse without adding more objects or consuming PGDATA.
        proxy.fault_hit.clear()
        proxy.fault_release.clear()
        proxy.fault_phase = 'payload'
        partial, partial_data, _ = start('partial-create', True)
        assert proxy.fault_hit.wait(90), 'partial creation never uploaded a payload'
        partial.kill()
        partial.wait(timeout=15)
        proxy.fault_phase = None
        proxy.fault_release.set()
        assert head() is None
        orphaned = inventory()
        assert orphaned
        for n in (1, 2):
            retry, retry_data, _ = start('partial-retry-'+str(n), True)
            assert retry.wait(timeout=20) != 0
            assert list(retry_data.glob('pg_wal/'+'?'*24)), 'refusal consumed initialized WAL'
            assert inventory() == orphaned, 'failed creation kept accumulating uploads'
        # Test-only reset after all creators are confirmed dead.
        for key in orphaned:
            run(['aws','--endpoint-url',args.endpoint,'s3api','delete-object','--bucket',args.bucket,'--key',prefix+key])
        shutil.rmtree(partial_data)

        # Both creators must pass the early absent-head check before either can publish.
        # Initialize both first to avoid setup time consuming the HTTP fault deadline.
        data_dirs = [root / ('data-race-' + str(n)) for n in (1, 2)]
        for data in data_dirs:
            run([pg / 'initdb', '-D', data, '-U', 'postgres', '-A', 'trust', '--no-locale', '--encoding=UTF8', '--data-checksums'])
        proxy.block.set()
        proxy.drop.set()
        proxy.race_listing.set()
        racers = [start('race-' + str(n), True, data_dirs[n-1]) for n in (1, 2)]
        with proxy.condition:
            assert proxy.condition.wait_for(lambda: len(proxy.pending) >= 2, timeout=90), f'creators never reached publication; inspect {root}'
        assert head() is None
        for process, _, sock in racers:
            assert process.poll() is None
            try:
                sql(sock, 'SELECT 1')
                raise AssertionError('creator admitted SQL before publication')
            except subprocess.CalledProcessError:
                pass
        proxy.block.clear()
        proxy.race_listing.clear()
        proxy.release.set()
        deadline = time.monotonic() + 30
        while all(process.poll() is None for process, _, _ in racers):
            assert time.monotonic() < deadline, 'competing creator did not stop'
            time.sleep(.1)
        winners = [item for item in racers if item[0].poll() is None]
        assert len(winners) == 1
        process, data, sock = winners[0]
        ready(process, sock)
        assert not proxy.drop.is_set(), 'lost initial PUT response was not exercised'
        sql(sock, 'CREATE TABLE created_here(id int primary key); INSERT INTO created_here VALUES (42)')
        sql(sock, 'BEGIN; INSERT INTO created_here VALUES (43); ROLLBACK')
        assert not list(data.glob('pg_wal/' + '?' * 24)), 'creation left local WAL segment files'
        original = head()
        # A new create request must refuse before touching its initialized WAL.
        refused, refused_data, _ = start('existing-head', True)
        assert refused.wait(timeout=20) != 0
        assert 'S3 archive already exists' in (root / 'native-existing-head.log').read_text()
        assert list(refused_data.glob('pg_wal/' + '?' * 24))
        expected_ids = {42}
        crash_results = []
        if args.crashes:
            sql(sock, 'CREATE TABLE crash_churn(id int PRIMARY KEY, n int); INSERT INTO crash_churn VALUES (1,0)')
            sentinel = root/'sentinel'
            sentinel.write_bytes(b'not a pgrust archive object')
            for key in ('notes.txt', 'neighbor/chunks/'+'0'*64):
                run(['aws','--endpoint-url',args.endpoint,'s3api','put-object','--bucket',args.bucket,'--key',prefix+key,'--body',sentinel])
            for cycle in range(args.crashes):
                phase = ('payload','index','metadata','head','delete')[cycle % 5]
                generation = json.loads(head()).get('generation', 0)
                value = 100 + cycle
                sql(sock, f'INSERT INTO created_here VALUES ({value})')
                expected_ids.add(value)
                proxy.fault_generation = generation
                proxy.fault_hit.clear()
                proxy.fault_release.clear()
                proxy.fault_phase = phase
                def crash_at_fault(victim=process):
                    if proxy.fault_hit.wait(90):
                        victim.kill()
                        proxy.fault_release.set()
                killer = threading.Thread(target=crash_at_fault, daemon=True)
                killer.start()
                # Separate connections keep switches from becoming one huge transaction.
                for _ in range(5):
                    if proxy.fault_hit.is_set():
                        break
                    try:
                        sql(sock, f'UPDATE crash_churn SET n={cycle}; SELECT pg_switch_wal()')
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        assert proxy.fault_hit.is_set(), 'SQL failed before the requested fault'
                        break
                assert proxy.fault_hit.wait(60), f'fault phase {phase} was not reached'
                killer.join(timeout=10)
                assert not killer.is_alive()
                process.kill()
                process.wait(timeout=15)
                proxy.fault_phase = None
                proxy.fault_release.set()
                stable = json.loads(head())
                live = reachable(stable)
                before = inventory()
                assert live <= before.keys(), 'selected recovery object was already missing'
                abandoned = {k for k in before if owned(k)} - live
                assert abandoned, f'{phase} produced no abandoned objects to test'
                shutil.rmtree(data)
                if args.startup_faults and cycle == 0:
                    fenced = hashlib.sha256(head()).hexdigest()
                    proxy.pending.clear()
                    proxy.release.clear()
                    proxy.block.set()
                    replacements = [start('replace-race-'+str(n), False, fenced=fenced) for n in (1,2)]
                    with proxy.condition:
                        assert proxy.condition.wait_for(lambda: len(proxy.pending)>=2, timeout=120), 'replacements did not reach the ownership CAS'
                    proxy.block.clear()
                    proxy.release.set()
                    deadline = time.monotonic()+120
                    while all(p.poll() is None for p,_,_ in replacements):
                        assert time.monotonic()<deadline, 'losing replacement did not stop'
                        time.sleep(.1)
                    winners = [item for item in replacements if item[0].poll() is None]
                    assert len(winners)==1
                    process, data, sock = winners[0]
                elif args.startup_faults and cycle == 1:
                    proxy.fault_hit.clear()
                    proxy.fault_release.clear()
                    proxy.fault_phase = 'delete'
                    victim, victim_data, _ = start('sweep-interrupted', False)
                    assert proxy.fault_hit.wait(120), 'startup sweep did not reach deletion'
                    victim.kill()
                    victim.wait(timeout=15)
                    proxy.fault_phase = None
                    proxy.fault_release.set()
                    if victim_data.exists(): shutil.rmtree(victim_data)
                    process, data, sock = start('sweep-resumed', False)
                else:
                    process, data, sock = start('crash-'+str(cycle), False)
                ready(process, sock)
                got = sql(sock, "SELECT string_agg(id::text,',' ORDER BY id) FROM created_here")
                assert got == ','.join(map(str,sorted(expected_ids))), (phase, got)
                after = inventory()
                # A new timeline can recreate its history object; other old
                # unselected names must disappear before SQL admission.
                assert not {k for k in abandoned if not k.startswith('histories/')} & after.keys(), 'abandoned uploads survived startup cleanup'
                assert 'notes.txt' in after and 'neighbor/chunks/'+'0'*64 in after
                assert sum(after.values()) < 512*1024*1024
                crash_results.append(dict(phase=phase, abandoned_objects=len(abandoned), bucket_bytes=sum(after.values())))
                print(json.dumps(crash_results[-1]), flush=True)
                # Finish a renewal between crashes so this test stresses crash
                # handling, rather than deliberately outrunning bounded WAL.
                generation = json.loads(head()).get('generation', 0)
                for _ in range(5):
                    sql(sock, f'UPDATE crash_churn SET n={cycle}; SELECT pg_switch_wal()')
                deadline = time.monotonic()+120
                while json.loads(head()).get('generation',0) <= generation:
                    assert process.poll() is None, 'post-crash maintenance stopped'
                    assert time.monotonic()<deadline, 'post-crash renewal timed out'
                    time.sleep(.2)
                # Let retirement's native checkpoint finish before arming the next fault.
                time.sleep(2)
        generations = []
        extended_relation = None
        if args.renewals:
            sql(sock, "CREATE TABLE renewal_data(id int PRIMARY KEY, n int, pad text); INSERT INTO renewal_data SELECT i,0,repeat(md5(i::text),32) FROM generate_series(1,2000) i")
            sql(sock, 'CREATE TABLE extension_probe(id int); INSERT INTO extension_probe VALUES(1)')
            for cycle in range(args.renewals):
                previous = json.loads(head())
                generation = previous.get('generation', 0)
                before_upload = proxy.backup_bytes
                if cycle == 1:
                    # Model native zero-filled relation extension: it can grow a
                    # file without adding modified blocks to a WAL summary.
                    name = sql(sock, "SELECT pg_relation_filepath('extension_probe')")
                    relation = data / name
                    length = relation.stat().st_size
                    with relation.open('ab') as output:
                        output.write(bytes(16 * 8192))
                    extended_relation = (name, length)
                if cycle == 0:
                    proxy.pause_snapshot.set()
                    proxy.drop_renewal.set()
                sql(sock, f"UPDATE renewal_data SET n={cycle+1} WHERE id<=10")
                sql(sock, f'CREATE TABLE IF NOT EXISTS renewal_churn(id int); TRUNCATE renewal_churn; INSERT INTO renewal_churn VALUES ({cycle}); CREATE TABLE dropped_during_renewal(id int); DROP TABLE dropped_during_renewal')
                for _ in range(5):
                    sql(sock, f'UPDATE renewal_data SET n={cycle+1} WHERE id<=10; SELECT pg_switch_wal()')
                    # Once paused, exercise the concurrent commit immediately;
                    # extra segment switches only consume the fault deadline.
                    if cycle == 0 and proxy.snapshot_pending.is_set():
                        break
                if cycle == 0:
                    assert proxy.snapshot_pending.wait(30), 'renewal upload never started'
                    # This commit must complete while snapshot upload is paused.
                    sql(sock, 'INSERT INTO created_here VALUES (45)')
                    expected_ids.add(45)
                    assert json.loads(head()).get('generation', 0) == generation
                    # Lose compute before the new snapshot can be selected. The
                    # old snapshot plus published WAL must still recover the commit.
                    process.kill()
                    process.wait(timeout=15)
                    shutil.rmtree(data)
                    proxy.pause_snapshot.clear()
                    proxy.snapshot_release.set()
                    process, data, sock = start('interrupted-export', False)
                    ready(process, sock)
                    assert sql(sock, 'SELECT count(*) FROM created_here WHERE id=45') == '1'
                deadline = time.monotonic() + 120
                while True:
                    assert process.poll() is None, f'renewal server exited; inspect {root}'
                    current = json.loads(head())
                    if current.get('generation', 0) > generation:
                        break
                    assert time.monotonic() < deadline, 'automatic renewal timed out'
                    time.sleep(.2)
                assert current['start'] > previous['start']
                generations.append(current['generation'])
                # Wait for deletion, not merely selecting a new snapshot.
                old = prefix + 'descriptors/' + previous['tail']
                while True:
                    try:
                        run(['aws', '--endpoint-url', args.endpoint, 's3api', 'get-object', '--bucket', args.bucket, '--key', old, root/'retired-probe'])
                    except subprocess.CalledProcessError as error:
                        assert 'NoSuchKey' in error.stderr, error.stderr
                        break
                    assert time.monotonic() < deadline, 'obsolete WAL was not deleted'
                    time.sleep(.2)
                stored = sum(inventory().values())
                assert stored < 512 * 1024 * 1024, 'bucket storage grew beyond the bounded workload budget'
                uploaded = proxy.backup_bytes - before_upload
                assert uploaded < 10 * 1024 * 1024, 'renewal recopied the full database'
                print(json.dumps(dict(cycle=cycle+1, generation=current['generation'], start=current['start'], end=current['end'], backup_bytes_uploaded=uploaded, bucket_bytes=stored)), flush=True)
            assert not proxy.drop_renewal.is_set(), 'lost renewal response was not exercised'
            old_lsn = json.loads(original)['start']
            # psql cannot consume CopyBoth and exits before the streaming read.
            # Use the wire protocol so we observe the server's actual read error.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as reader:
                reader.settimeout(10)
                reader.connect(str(sock / '.s.PGSQL.55441'))
                def exact(n):
                    out = b''
                    while len(out) < n:
                        part = reader.recv(n-len(out))
                        assert part, 'replication connection closed without an error'
                        out += part
                    return out
                def message():
                    kind = exact(1)
                    size = struct.unpack('!I', exact(4))[0]
                    assert 4 <= size <= 1024*1024
                    return kind, exact(size-4)
                startup = struct.pack('!I', 196608) + b'user\0postgres\0database\0postgres\0replication\0true\0\0'
                reader.sendall(struct.pack('!I', len(startup)+4)+startup)
                while True:
                    kind, body = message()
                    assert kind != b'E', body
                    if kind == b'Z':
                        break
                query = f'START_REPLICATION {old_lsn >> 32:X}/{old_lsn & 0xffffffff:X}'.encode()+b'\0'
                reader.sendall(b'Q'+struct.pack('!I',len(query)+4)+query)
                while True:
                    kind, body = message()
                    assert kind != b'd', 'retired WAL was still streamable'
                    if kind == b'E':
                        assert b'already been removed' in body or b'could not read from WAL' in body, body
                        break
            assert sql(sock, 'SELECT 1') == '1', 'retired-WAL request crashed compute'
        process.kill()
        process.wait(timeout=15)
        for _, local, _ in racers:
            if local.exists():
                shutil.rmtree(local)
        if data.exists():
            shutil.rmtree(data)
        restored, restored_data, restored_sock = start('restored', False)
        ready(restored, restored_sock)
        assert sql(restored_sock, 'SELECT string_agg(id::text,\',\' ORDER BY id) FROM created_here') == ','.join(map(str,sorted(expected_ids)))
        if args.renewals:
            assert sql(restored_sock, 'SELECT sum(n) FROM renewal_data') == str(args.renewals * 10)
            assert sql(restored_sock, 'SELECT count(*) FROM renewal_data') == '2000'
            if extended_relation:
                name, length = extended_relation
                content = (restored_data / name).read_bytes()
                assert content[length:] == bytes(16 * 8192), 'snapshot lost zero-filled extension'
                assert sql(restored_sock, 'SELECT id FROM extension_probe') == '1'
            assert sql(restored_sock, "SELECT count(*) FROM pg_indexes WHERE tablename='renewal_data' AND indexname='renewal_data_pkey'") == '1'
            plan = sql(restored_sock, 'SET enable_seqscan=off; EXPLAIN SELECT n FROM renewal_data WHERE id=1')
            assert 'Index Scan' in plan or 'Bitmap' in plan, plan
            assert sql(restored_sock, 'SET enable_seqscan=off; SELECT n FROM renewal_data WHERE id=1').splitlines()[-1] == str(args.renewals)
            try:
                sql(restored_sock, 'INSERT INTO renewal_data(id) VALUES(1)')
            except subprocess.CalledProcessError as error:
                assert 'duplicate key' in error.stderr, error.stderr
            else:
                raise AssertionError('restored primary key was not enforced')
            assert sql(restored_sock, 'SELECT id FROM renewal_churn') == str(args.renewals-1)
            assert sql(restored_sock, "SELECT to_regclass('dropped_during_renewal') IS NULL") == 't'
        sql(restored_sock, 'INSERT INTO created_here VALUES (44)')
        expected_ids.add(44)
        assert not list(restored_data.glob('pg_wal/' + '?' * 24))
        if args.renewals:
            generation = json.loads(head()).get('generation', 0)
            proxy.delete_generation = generation + 1
            for _ in range(5):
                sql(restored_sock, f'UPDATE renewal_data SET n={args.renewals+1} WHERE id<=10; SELECT pg_switch_wal()')
            deadline = time.monotonic() + 120
            while json.loads(head()).get('generation', 0) <= generation:
                assert restored.poll() is None, f'recovered renewal failed; inspect {root}'
                assert time.monotonic() < deadline, 'recovered timeline did not renew'
                time.sleep(.2)
            assert proxy.delete_pending.wait(10), 'retirement interruption was not exercised'
            restored.kill()
            restored.wait(timeout=15)
            proxy.delete_generation = None
            proxy.delete_release.set()
            shutil.rmtree(restored_data)
            again, again_data, again_sock = start('restored-again', False)
            ready(again, again_sock)
            assert sql(again_sock, "SELECT string_agg(id::text,',' ORDER BY id) FROM created_here") == ','.join(map(str,sorted(expected_ids)))
            assert sql(again_sock, 'SELECT sum(n) FROM renewal_data') == str((args.renewals+1)*10)
        print(json.dumps(dict(result='passed', prefix=prefix, partial_creation_refused=True, crashes=crash_results, startup_faults=args.startup_faults, failed_upload_no_head=True,
                              concurrent_creators_one_winner=True, lost_initial_response=True,
                              sql_closed_before_publication=True, recovered_committed_row=42,
                              rollback_absent=True, recovery_continued=True, renewal_generations=generations, interrupted_export_recovered=bool(args.renewals), interrupted_retirement_recovered=bool(args.renewals))), flush=True)
    finally:
        proxy.release.set()
        proxy.list_release.set()
        proxy.fault_release.set()
        proxy.snapshot_release.set()
        proxy.delete_release.set()
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=15)
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    main()
