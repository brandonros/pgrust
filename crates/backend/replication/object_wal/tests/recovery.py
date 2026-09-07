"""Independent MinIO integration test. PostgreSQL tools are test oracles only.
Build first: cargo build --offline -p main_main --bin postgres
Exports a native full backup and two increments, verifies them with stock tools, then
runs the native server twice with fresh PGDATA. No runtime helper processes.
"""
import argparse, hashlib, http.client, http.server, json, os, pathlib, re, shutil, signal, socket as sockets, subprocess, tempfile, threading, time, urllib.parse, uuid
P = pathlib.Path
SEG = 16 * 1024 * 1024

def digest(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':')).encode()

def lsn(s):
    (a, b) = s.strip().split('/')
    return int(a, 16) << 32 | int(b, 16)

def loc(n):
    return f'{n >> 32:X}/{n & 4294967295:X}'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', default='target/debug/postgres')
    ap.add_argument('--pg-bin', required=True)
    ap.add_argument('--sharedir', required=True)
    ap.add_argument('--endpoint', default='http://127.0.0.1:9000')
    ap.add_argument('--bucket', default='pgrust-wal-experiments')
    a = ap.parse_args()
    root = P(tempfile.mkdtemp(prefix='native-s3-', dir='/tmp'))
    print(root, flush=True)
    pg = P(a.pg_bin)
    server = P(a.server).resolve()
    prefix = 'native-' + uuid.uuid4().hex + '/'
    (root / 'prefix').write_text(prefix)
    env = os.environ.copy()
    env.update(AWS_ACCESS_KEY_ID='minioadmin', AWS_SECRET_ACCESS_KEY='minioadmin', AWS_DEFAULT_REGION='us-east-1', PGRUST_PGSHAREDIR=a.sharedir, PGRUST_TZDIR='/usr/share/zoneinfo', RUST_MIN_STACK='33554432', PGCONNECT_TIMEOUT='2')
    env.pop('AWS_SESSION_TOKEN', None)
    for k in list(env):
        if k.startswith('PG') and k not in ('PGCONNECT_TIMEOUT',) and (not k.startswith('PGRUST_')):
            env.pop(k, None)

    def run(argv, **kw):
        return subprocess.run(list(map(str, argv)), env=env, check=True, capture_output=True, text=True, timeout=kw.pop('timeout', 180), **kw).stdout.strip()

    def aws(*args):
        return run(['aws', '--endpoint-url', a.endpoint, 's3api', *args])
    counter = 0

    def put(key, b):
        nonlocal counter
        path = root / f'upload-{counter}'
        counter += 1
        path.write_bytes(b)
        aws('put-object', '--bucket', a.bucket, '--key', prefix + key, '--body', path, '--if-none-match', '*')
        path.unlink()

    seed = root / 'seed'
    def imm(kind, b):
        key = digest(b)
        path = seed / kind / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b)
        return key

    def head():
        path = root / 'head-download'
        aws('get-object', '--bucket', a.bucket, '--key', prefix + 'head', path)
        return path.read_bytes()

    def sql(socket, port, q):
        return run([pg / 'psql', '-XAt', '-h', socket, '-p', port, '-U', 'postgres', '-d', 'postgres', '-c', q], timeout=30)
    processes = []
    endpoint = urllib.parse.urlsplit(a.endpoint)

    class Proxy(http.server.BaseHTTPRequestHandler):

        def log_message(self, *args):
            # Never log signed URLs.
            pass

        def do_GET(self):
            self.exchange()

        def do_PUT(self):
            self.exchange()

        def do_DELETE(self):
            self.exchange()

        def exchange(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            is_head = self.command == 'PUT' and self.path.split('?', 1)[0].endswith('/head')
            if is_head and proxy.block.is_set():
                proxy.block.clear()
                proxy.pending.set()
                proxy.release.wait(4)
            connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port or 80, timeout=10)
            try:
                connection.request(self.command, self.path, body=body, headers=dict(self.headers))
                response = connection.getresponse()
                data = response.read()
                if self.command == 'GET' and '/backup-chunks/' in self.path and proxy.corrupt.is_set():
                    data = b'corrupted archive chunk'
                if is_head and proxy.drop.is_set():
                    proxy.drop.clear()
                    proxy.dropped += 1
                    self.close_connection = True
                    self.connection.shutdown(sockets.SHUT_RDWR)
                    return
                self.send_response(response.status)
                for (k, v) in response.getheaders():
                    if k.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                        self.send_header(k, v)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                connection.close()
    proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    proxy.corrupt = threading.Event()
    proxy.block = threading.Event()
    proxy.pending = threading.Event()
    proxy.release = threading.Event()
    proxy.drop = threading.Event()
    proxy.dropped = 0
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    native_endpoint = f'http://127.0.0.1:{proxy.server_port}'
    try:
        source = root / 'source'
        sock = root / 'source-socket'
        sock.mkdir()
        run([pg / 'initdb', '-D', source, '-U', 'postgres', '-A', 'trust', '--no-locale', '--encoding=UTF8', '--data-checksums'])
        with (source / 'postgresql.conf').open('a') as f:
            f.write(f"\nlisten_addresses=''\nunix_socket_directories='{sock}'\nport=55439\nsummarize_wal=on\nio_method=sync\nshared_buffers=16MB\nmax_stack_depth=6000\nlog_min_messages=debug1\nwal_keep_size='128MB'\n")
        with (root / 'source.log').open('w') as log:
            source_process = subprocess.Popen([str(server), '-D', str(source)], env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(source_process)
        deadline = time.monotonic() + 60
        while True:
            assert source_process.poll() is None, f'native disk source stopped; inspect {root}'
            try:
                sql(sock, 55439, 'SELECT 1')
                break
            except subprocess.CalledProcessError:
                assert time.monotonic() < deadline, 'native disk source startup timed out'
                time.sleep(.1)


        def source_sql(q):
            return sql(sock, 55439, q)
        source_sql("CREATE TABLE native_s3_ledger(id int primary key, body text); INSERT INTO native_s3_ledger VALUES (1,'baseline'); CREATE TABLE sparse(id int primary key, body text); INSERT INTO sparse SELECT n, repeat(md5(n::text),100) FROM generate_series(1,4096) n; CHECKPOINT; SELECT count(*) FROM sparse;")
        full = root / 'full'
        inc = root / 'increment'
        run([pg / 'pg_basebackup', '-h', sock, '-p', '55439', '-U', 'postgres', '-D', full, '-X', 'none', '--checkpoint=fast'])
        # A zero-filled extension need not appear in a WAL summary. The stock
        # combiner independently checks how those absent predecessor pages work.
        relation = source / source_sql("SELECT pg_relation_filepath('sparse')")
        with relation.open('ab') as output:
            output.write(bytes(16 * 8192))
        source_sql("UPDATE sparse SET body='changed' WHERE id=10; INSERT INTO native_s3_ledger VALUES (2,'increment');")
        run([pg / 'pg_basebackup', '-h', sock, '-p', '55439', '-U', 'postgres', '-D', inc, '-X', 'none', '--checkpoint=fast', '--incremental', full / 'backup_manifest'])
        second = root / 'increment-two'
        source_sql("UPDATE sparse SET body='second change' WHERE id=20;")
        run([pg / 'pg_basebackup', '-h', sock, '-p', '55439', '-U', 'postgres', '-D', second, '-X', 'none', '--checkpoint=fast', '--incremental', inc / 'backup_manifest'])
        combined = root / 'combined'
        run([pg / 'pg_combinebackup', '-o', combined, full, inc, second])
        run([pg / 'pg_verifybackup', '-n', combined])
        source_sql("INSERT INTO native_s3_ledger VALUES (3,'WAL after snapshot');")
        source_sql("BEGIN; INSERT INTO native_s3_ledger VALUES (4,'abort'); ROLLBACK;")
        assert source_sql("SELECT string_agg(id::text,',' ORDER BY id) FROM native_s3_ledger") == '1,2,3'
        source_sql('SELECT pg_switch_wal();')
        end = lsn(source_sql('SELECT pg_current_wal_flush_lsn()'))
        manifest = json.loads((combined / 'backup_manifest').read_bytes())
        ranges = manifest['WAL-Ranges']
        assert len(ranges) == 1
        start = lsn(ranges[0]['Start-LSN'])
        base = start - start % SEG
        dump = run([pg / 'pg_waldump', '-p', source / 'pg_wal', '-s', loc(base), '-e', loc(end)])
        recs = re.findall('lsn:\\s*([0-9A-F]+/[0-9A-F]+)', dump)
        assert recs
        record = lsn(recs[-1])
        system = str(manifest['System-Identifier'])
        wal = bytearray()
        for pos in range(base, end, SEG):
            seg = pos // SEG
            name = f'{1:08X}{seg // 256:08X}{seg % 256:08X}'
            wal.extend((source / 'pg_wal' / name).read_bytes()[:min(SEG, end - pos)])
        chunk = imm('chunks', wal)
        desc = dict(cluster=system, timeline=1, start=base, end=end, record_start=record, previous=None, chunk=chunk)
        tail = imm('descriptors', encode(desc))

        # Test-only independent encoder for the one supported flat snapshot.
        # Stock pg_combinebackup above is the oracle for pgrust's exporter.
        files, dirs = {}, []
        salt = uuid.uuid4().hex.encode()
        for path in sorted(combined.rglob('*')):
            name = path.relative_to(combined).as_posix()
            if path.is_dir():
                dirs.append(name)
            elif name != 'backup_manifest' and not name.startswith('pg_wal/'):
                pieces = []
                content = path.read_bytes()
                for offset in range(0, len(content), 128*1024):
                    chunk = content[offset:offset+128*1024]
                    key = imm('backup-chunks', salt + chunk)
                    for page in range(0, len(chunk), 8192):
                        pieces.append(dict(key=key, offset=32+page, length=min(8192,len(chunk)-page)))
                files[name] = pieces
        image = dict(files=files, dirs=dirs, system=int(system), ranges=ranges)
        inventory = [dict(Path=name, Size=sum(p['length'] for p in pieces)) for name,pieces in files.items()]
        mbody = b'{"PostgreSQL-Backup-Manifest-Version":2,"System-Identifier":'+system.encode()+b',\n"Files":'+encode(inventory)+b',\n"WAL-Ranges":'+encode(ranges)+b',\n'
        mbytes = mbody+b'"Manifest-Checksum":"'+digest(mbody).encode()+b'"}\n'
        info = dict(version=2, cluster=system, timeline=1, start=start, end=lsn(ranges[0]['End-LSN']), manifest=digest(mbytes), anchor=tail, archive_start=base, seed_end=end, seed_record_start=record, root_history=None, image=imm('snapshot-index', encode(image)))
        backup = imm('backups', encode(info))
        # Independent fixture data goes into a fresh, private prefix in one
        # CLI invocation. Publish the conditional head only after every object.
        run(['aws', '--endpoint-url', a.endpoint, 's3', 'cp', seed,
             f's3://{a.bucket}/{prefix}', '--recursive', '--only-show-errors'])
        shutil.rmtree(seed)
        put('head', encode(dict(version=2, cluster=system, timeline=1, start=base, end=end, record_start=record, tail=tail, backup=backup, epoch=uuid.uuid4().hex, revision=uuid.uuid4().hex)))
        relation = source_sql("SELECT pg_relation_filepath('sparse')")
        reads = re.findall(r'base backup file '+re.escape(str(P(relation).parent / ('INCREMENTAL.'+P(relation).name)))+r': source bytes read (\d+), output bytes (\d+)', (root/'source.log').read_text())
        assert len(reads) == 2 and all(int(n)<(source/relation).stat().st_size//10 for n,_ in reads), reads
        expected = source_sql("SELECT md5(string_agg(id::text || body,'' ORDER BY id)) FROM sparse")
        source_process.kill()
        source_process.wait(timeout=15)
        shutil.rmtree(source)
        shutil.rmtree(full)
        shutil.rmtree(inc)
        shutil.rmtree(second)
        shutil.rmtree(combined)
        oracle = root / 'expected.json'
        oracle.write_text(json.dumps({'fingerprint': expected, 'ledger': [1, 2, 3]}))

        def start_native(n, fenced=None, extra=None):
            config = root / f'config-{n}'
            config.mkdir()
            socket = root / f'socket-{n}'
            socket.mkdir()
            data = root / f'data-{n}'
            values = dict(data_directory=str(data), hba_file=str(config / 'pg_hba.conf'), ident_file=str(config / 'pg_ident.conf'), listen_addresses='', unix_socket_directories=str(socket), port='55440', io_method='sync', max_stack_depth='6000', shared_buffers='16MB', max_connections='16', wal_level='replica', max_wal_senders='4', max_replication_slots='4', fsync='on', synchronous_commit='on', restart_after_crash='off', hot_standby='off', synchronous_standby_names='', summarize_wal='on', **{'pgrust.strict_synchronous_commit': 'on', 'pgrust.memory_wal': '256MB', 'pgrust.s3': 'on', 'pgrust.s3_endpoint': native_endpoint, 'pgrust.s3_bucket': a.bucket, 'pgrust.s3_prefix': prefix, 'pgrust.s3_fenced_head': fenced or digest(head())})
            if extra:
                values.update(extra)
            (config / 'postgresql.conf').write_text('\n'.join((k + " = '" + v.replace("'", "''") + "'" for (k, v) in values.items())) + '\n')
            (config / 'pg_hba.conf').write_text('local all all trust\nlocal replication all trust\n')
            (config / 'pg_ident.conf').touch()
            log = (root / f'native-{n}.log').open('w')
            p = subprocess.Popen([str(server), '-D', str(config)], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            log.close()
            processes.append(p)
            return (p, data, socket)
        (bad, bad_data, _) = start_native('stale', fenced='0' * 64)
        assert bad.wait(timeout=20) != 0 and (not bad_data.exists()), 'stale authorization exposed PGDATA'
        before = head()
        proxy.corrupt.set()
        (bad, bad_data, _) = start_native('corrupt')
        assert bad.wait(timeout=30) != 0 and (not bad_data.exists()), 'corrupt restore exposed PGDATA'
        assert head() == before and (not list(root.glob('.data-corrupt.restore-*')))
        proxy.corrupt.clear()
        for n in [1, 2]:
            (p, data, socket) = start_native(n, extra={'allow_in_place_tablespaces': 'on'})
            deadline = time.monotonic() + 120
            while True:
                if p.poll() is not None:
                    raise RuntimeError(f'native {n} exited; see {root}/native-{n}.log')
                try:
                    got = sql(socket, 55440, "SELECT string_agg(id::text,',' ORDER BY id) FROM native_s3_ledger")
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('native startup timed out')
                    time.sleep(0.1)
            assert got == ('1,2,3' if n == 1 else '1,2,3,5,7,8'), got
            assert sql(socket, 55440, "SELECT md5(string_agg(id::text || body,'' ORDER BY id)) FROM sparse") == expected
            if n == 1:
                external = root / 'external-tablespace'
                external.mkdir()
                for query, message in [
                    (f"CREATE TABLESPACE outside LOCATION '{external}'", 'tablespaces are not supported'),
                    ("CREATE TABLESPACE inside LOCATION ''", 'tablespaces are not supported'),
                    ('SET synchronous_commit=off', 'cannot be changed'),
                    ('SET fsync=off', 'cannot be changed'),
                    ('SET restart_after_crash=on', 'cannot be changed'),
                    ("SET synchronous_standby_names='replacement'", 'cannot be changed'),
                ]:
                    try:
                        sql(socket, 55440, query)
                    except subprocess.CalledProcessError as error:
                        assert message in error.stderr, error.stderr
                    else:
                        raise AssertionError('S3 recovery/durability restriction was bypassed')
            proxy.drop.set()
            sql(socket, 55440, f"INSERT INTO native_s3_ledger VALUES ({(5 if n == 1 else 6)},'native acknowledged');")
            assert not proxy.drop.is_set(), 'lost-response fault was not exercised'
            if n == 1:
                before = head()
                proxy.pending.clear()
                proxy.release.clear()
                proxy.block.set()
                client = subprocess.Popen([str(pg / 'psql'), '-XAt', '-h', str(socket), '-p', '55440', '-U', 'postgres', '-d', 'postgres', '-c', "INSERT INTO native_s3_ledger VALUES (7,'cancelled wait still requires durability');"], env=dict(env, PGAPPNAME='blocked_s3'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(client)
                assert proxy.pending.wait(5), 'publisher did not reach blocked head PUT'
                assert head() == before
                assert sql(socket, 55440, 'SELECT count(*) FROM native_s3_ledger WHERE id=7') == '0'
                assert sql(socket, 55440, "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE application_name='blocked_s3'") == 't'
                time.sleep(0.2)
                assert client.poll() is None, 'cancellation acknowledged before bucket durability'
                proxy.release.set()
                (out, err) = client.communicate(timeout=20)
                assert client.returncode == 0, (out, err)
                assert head() != before
                sql(socket, 55440, 'CREATE SEQUENCE cached_sequence CACHE 10')
                for app, query, terminate in [
                    ('cached_sequence_wait', "BEGIN; SELECT nextval('cached_sequence'); ROLLBACK; SELECT nextval('cached_sequence')", False),
                    ('terminated_s3_wait', "INSERT INTO native_s3_ledger VALUES (8,'terminated while waiting')", True),
                ]:
                    proxy.pending.clear()
                    proxy.release.clear()
                    proxy.block.set()
                    client = subprocess.Popen([str(pg/'psql'), '-XAt', '-h', str(socket), '-p', '55440', '-U', 'postgres', '-d', 'postgres', '-c', query], env=dict(env, PGAPPNAME=app), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    processes.append(client)
                    assert proxy.pending.wait(5), 'publisher did not reach blocked PUT'
                    deadline = time.monotonic() + 2
                    while sql(socket, 55440, f"SELECT count(*) FROM pg_stat_activity WHERE application_name='{app}' AND wait_event='SyncRep'") != '1':
                        assert client.poll() is None, 'strict dependency completed before publication'
                        assert time.monotonic() < deadline, 'strict dependency never waited'
                        time.sleep(.05)
                    if terminate:
                        assert sql(socket, 55440, f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='{app}'") == 't'
                        time.sleep(.2)
                        assert client.poll() is None, 'termination bypassed strict completion'
                    proxy.release.set()
                    out, err = client.communicate(timeout=20)
                    if terminate:
                        assert client.returncode != 0, (out, err)
                        assert sql(socket, 55440, 'SELECT count(*) FROM native_s3_ledger WHERE id=8') == '1'
                    else:
                        assert client.returncode == 0 and out.splitlines()[-1] == '2', (out, err)
                # Renew an independently encoded snapshot during native writes.
                for _ in range(5):
                    sql(socket, 55440, 'UPDATE sparse SET body=body WHERE id=1; SELECT pg_switch_wal()')
                deadline = time.monotonic() + 120
                while json.loads(head()).get('generation', 0) == 0:
                    assert p.poll() is None, f'snapshot renewal failed; inspect {root}'
                    assert time.monotonic() < deadline, 'snapshot did not renew'
                    time.sleep(.2)
            assert not list(data.glob('pg_wal/' + '?' * 24)), 'memory mode created WAL segment files'
            if n == 2:
                assert int(sql(socket, 55440, "SELECT nextval('cached_sequence')")) > 2, 'recovery reused an acknowledged sequence value'
                # Mutate only this fixture's prefix to simulate ownership loss.
                value = json.loads(head())
                value['epoch'] = uuid.uuid4().hex
                value['revision'] = uuid.uuid4().hex
                path = root / 'competing-head'
                path.write_bytes(encode(value))
                aws('put-object', '--bucket', a.bucket, '--key', prefix + 'head', '--body', path)
                assert p.wait(timeout=20) != 0, 'ownership loss did not stop the server'
            else:
                p.kill()
                p.wait(timeout=15)
            shutil.rmtree(data)
        plain = root / 'ordinary-data'
        run([pg / 'initdb', '-D', plain, '-U', 'postgres', '-A', 'trust', '--no-locale', '--encoding=UTF8'])
        for n in [1, 2, 3]:
            ordinary = {'data_directory': str(plain), 'pgrust.s3': 'off', 'pgrust.memory_wal': '0', 'pgrust.strict_synchronous_commit': 'off'}
            if n == 1:
                ordinary.update(synchronous_standby_names='unavailable', synchronous_commit='local')
            (p, _, socket) = start_native('disk-' + str(n), extra=ordinary)
            deadline = time.monotonic() + 30
            while True:
                assert p.poll() is None, 'ordinary native startup failed'
                try:
                    sql(socket, 55440, 'SELECT 1')
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('ordinary startup timed out')
                    time.sleep(0.1)
            if n == 1:
                sql(socket, 55440, 'CREATE TABLE ordinary(id int); INSERT INTO ordinary VALUES(42); CHECKPOINT')
                # Ordinary synchronous replication retains its cancellable wait.
                client = subprocess.Popen([str(pg/'psql'), '-XAt', '-h', str(socket), '-p', '55440', '-U', 'postgres', '-d', 'postgres', '-c', 'SET synchronous_commit=on; INSERT INTO ordinary VALUES(99)'], env=dict(env, PGAPPNAME='ordinary_cancel'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(client)
                deadline = time.monotonic()+10
                while sql(socket, 55440, "SELECT count(*) FROM pg_stat_activity WHERE application_name='ordinary_cancel' AND wait_event='SyncRep'") != '1':
                    assert client.poll() is None, 'ordinary synchronous commit did not wait'
                    assert time.monotonic()<deadline, 'ordinary synchronous wait was not reached'
                    time.sleep(.1)
                assert sql(socket, 55440, "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE application_name='ordinary_cancel'") == 't'
                out, err = client.communicate(timeout=10)
                assert client.returncode == 0 and 'canceling wait for synchronous replication' in err, (out,err)
            assert sql(socket, 55440, "SELECT string_agg(id::text,',' ORDER BY id) FROM ordinary") == ('42,43,44,99' if n == 3 else '42,99')
            assert sql(socket, 55440, 'SET synchronous_commit=off; SHOW synchronous_commit').splitlines()[-1] == 'off'
            assert list(plain.glob('pg_wal/'+'?'*24))
            if n == 2:
                sql(socket, 55440, 'INSERT INTO ordinary VALUES(43); CHECKPOINT; INSERT INTO ordinary VALUES(44)')
                p.kill()
                assert p.wait(timeout=30) != 0
            else:
                p.send_signal(signal.SIGINT)
                assert p.wait(timeout=30) == 0
        shutil.rmtree(plain)
        print(json.dumps({'result': 'passed', 'prefix': prefix, 'source_removed': True, 'native_full_plus_two_increments': True, 'stock_combine_and_verify': True, 'increment_source_reads': reads, 'independent_snapshot_renewed': True, 'recovery_cycles': 2, 'native_commits': [5, 7, 6], 'lost_head_responses': proxy.dropped, 'ordinary_disk_restart': True, 'ordinary_disk_crash_recovery': True, 'ordinary_syncrep_cancel': True, 'corrupt_restore_rejected': True, 'cancel_wait_checked': True, 'cached_sequence_wait_checked': True, 'termination_wait_checked': True, 'ownership_loss_stopped_server': True, 'fingerprint': expected}), flush=True)
    finally:
        proxy.release.set()
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(timeout=5)
        for p in processes:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=15)
        source = root / 'source'
        if (source / 'postmaster.pid').exists():
            subprocess.run([str(pg / 'pg_ctl'), '-D', str(source), '-m', 'immediate', '-w', 'stop'], env=env, capture_output=True)
if __name__ == '__main__':
    main()
