#!/usr/bin/env python3
"""Run from a normal terminal: nix develop -c python3 scripts/test_s3_wal.py

Runs native/default-feature workspace tests under their normal test contract, then the
unmodified PostgreSQL 18.3 regression and isolation schedules on separate S3
clusters. No expected-result overlays. All artifacts and bucket prefixes are
retained for diagnosis. Requires Cargo, AWS CLI, PostgreSQL 18.3 clients and its
installed pg_regress/pg_isolation_regress/isolationtester binaries. Ignored Rust
entries are reported separately; child probes must run through their parents.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid


VERSION = "18.3"
REPO = Path(__file__).resolve().parents[1]


def stop_group(process, sig=signal.SIGTERM):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


class Run:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="pgrust-s3-suites-", dir="/tmp")).resolve()
        self.log = (self.root / "run.log").open("w", buffering=1)
        self.lock = threading.Lock()
        self.results = {}
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        self.env.update(LC_ALL="C", LANG="C", RUST_MIN_STACK="33554432",
                        PGCONNECT_TIMEOUT="3", AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off",
                        PGRUST_PGSHAREDIR=args.sharedir,
                        PGRUST_TZDIR=os.getenv("PGRUST_TZDIR", "/usr/share/zoneinfo"))
        if args.endpoint in ("http://127.0.0.1:9000", "http://localhost:9000"):
            # Match the explicitly selected local MinIO, not ambient cloud credentials.
            self.env.update(AWS_ACCESS_KEY_ID=os.getenv("OBJKV_S3_KEY", "minioadmin"),
                            AWS_SECRET_ACCESS_KEY=os.getenv("OBJKV_S3_SECRET", "minioadmin"))
            self.env.pop("AWS_SESSION_TOKEN", None)
        self.env["AWS_DEFAULT_REGION"] = args.region
        self.say("Artifacts and combined log: " + str(self.root))

    def say(self, text):
        with self.lock:
            print(text, flush=True)
            self.log.write(text + "\n")

    def command(self, name, command, cwd=None, timeout=None, monitor=None):
        self.say("\n[" + name + "] " + shlex.join(list(map(str, command))))
        with (self.root / (name + ".log")).open("w") as output:
            process = subprocess.Popen(list(map(str, command)), cwd=cwd or REPO,
                                       env=self.env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True,
                                       errors="replace", start_new_session=True)

            def drain():
                warnings = 0
                for line in process.stdout:
                    output.write(line)
                    output.flush()
                    if command[0] == "cargo":
                        try:
                            event = json.loads(line)
                        except ValueError:
                            event = None
                        if isinstance(event, dict) and "reason" in event:
                            if event["reason"] == "compiler-message":
                                diagnostic = event["message"]
                                if diagnostic["level"] == "warning":
                                    warnings += 1
                                else:
                                    self.say(diagnostic.get("rendered") or diagnostic["message"])
                            continue
                    self.say(line.rstrip("\n"))
                if warnings:
                    self.say("[%s] Suppressed %d compiler warnings; full diagnostics: %s" %
                             (name, warnings, self.root / (name + ".log")))

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            deadline = time.monotonic() + (timeout or self.args.timeout)
            heartbeat = time.monotonic() + 30
            try:
                while process.poll() is None:
                    if monitor:
                        monitor()
                    if time.monotonic() >= deadline:
                        raise RuntimeError(name + " timed out; remaining tests are NOT RUN")
                    if time.monotonic() >= heartbeat:
                        self.say("[" + name + "] still running; log: " + str(self.root / (name + ".log")))
                        heartbeat = time.monotonic() + 30
                    time.sleep(.25)
                if monitor:
                    monitor()
                return process.returncode
            finally:
                # Also terminate descendants if their parent exited or timed out.
                stop_group(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    stop_group(process, signal.SIGKILL)
                    process.wait()
                reader.join(timeout=5)
                if reader.is_alive():
                    stop_group(process, signal.SIGKILL)
                    reader.join(timeout=5)

    def capture(self, command, timeout=30):
        result = subprocess.run(list(map(str, command)), env=self.env, cwd=REPO,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "command failed: " + str(command[0]))
        return result.stdout.strip()

    def phase(self, name, operation):
        try:
            code = operation()
            self.results[name] = "PASS" if not code else "FAIL (exit %s)" % code
        except Exception as error:
            self.results[name] = "FAIL/BLOCKED: " + str(error)
        self.say(name + ": " + self.results[name])
        self.save_summary()

    def save_summary(self):
        (self.root / "summary.json").write_text(json.dumps(self.results, indent=2) + "\n")

    def workspace(self, common):
        try:
            return self.command("workspace", ["cargo", "test", "--workspace",
                                "--no-fail-fast", *common])
        finally:
            path = self.root / "workspace.log"
            if path.exists():
                target, ignored = "unknown target", []
                for line in path.read_text(errors="replace").splitlines():
                    if line.lstrip().startswith(("Running ", "Doc-tests ")):
                        target = line.strip()
                    if re.match(r"test .* \.\.\. ignored\b", line):
                        ignored.append(target + ": " + line)
                (self.root / "workspace-ignored.txt").write_text("\n".join(ignored) + "\n")
                if ignored:
                    self.say("Ignored Rust entries (child probes may run through their parent tests):\n"
                             + "\n".join(ignored))
                    self.results["workspace-coverage"] = (
                        "INCOMPLETE: %d ignored entries require individual accounting; see workspace-ignored.txt"
                        % len(ignored))

    def aws(self, *arguments):
        return ["aws", "--endpoint-url", self.args.endpoint, "--region", self.args.region,
                "--cli-connect-timeout", "5", "--cli-read-timeout", "15", *arguments]

    def prerequisites(self):
        pg = Path(self.args.pg_bin)
        tests = Path(self.args.pg_tests)
        for binary in (pg / "initdb", pg / "psql", pg / "pg_dump",
                       tests / "regress/pg_regress", tests / "isolation/pg_isolation_regress",
                       tests / "isolation/isolationtester"):
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError("missing executable: " + str(binary))
            version = self.capture([binary, "-V"])
            if not re.search(r"\b" + re.escape(VERSION) + r"\b", version):
                raise RuntimeError("expected PostgreSQL 18.3: " + version)
        if not Path(self.args.sharedir, "postgres.bki").is_file():
            raise RuntimeError("--sharedir must contain PostgreSQL 18.3 postgres.bki")
        if not shutil.which("aws"):
            raise RuntimeError("AWS CLI is required for test setup and archive assertions")
        self.env.update(PGRUST_PGSHAREDIR=self.args.sharedir,
                        PATH=str(pg) + os.pathsep + self.env["PATH"])
        # Require an existing bucket; never mutate another bucket's configuration.
        self.capture(self.aws("s3api", "head-bucket", "--bucket", self.args.bucket))
        source = Path(self.args.test_source).resolve()
        configure = source.parent.parent / "configure.ac"
        if not configure.is_file() or not re.search(
                r"AC_INIT\(\[PostgreSQL\],\s*\[" + re.escape(VERSION) + r"\]",
                configure.read_text()):
            raise RuntimeError("--test-source must be PostgreSQL " + VERSION + " src/test")
        for schedule in ("regress/parallel_schedule", "isolation/isolation_schedule"):
            if not (source / schedule).is_file():
                raise RuntimeError("missing upstream schedule: " + str(source / schedule))
        self.source = source
        self.say("PostgreSQL " + VERSION + " test sources: " + str(source))
        return 0

    def sql(self, socket, query):
        return self.capture([Path(self.args.pg_bin) / "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
                             "-h", socket, "-p", "55449", "-U", "postgres", "-d", "postgres",
                             "-c", query], timeout=15)

    def check_mode(self, socket, data, prefix):
        values = self.sql(socket, "SELECT current_setting('pgrust.s3'), "
                          "current_setting('pgrust.memory_wal'), "
                          "current_setting('pgrust.strict_synchronous_commit'), "
                          "current_setting('synchronous_commit'), current_setting('fsync'), "
                          "current_setting('restart_after_crash'), "
                          "current_setting('data_directory'), current_setting('pgrust.s3_prefix');")
        self.say("Mode assertion: " + values)
        fields = values.split("|")
        if fields != ["on", self.args.memory_wal, "on", "on", "on", "off", str(data), prefix]:
            raise RuntimeError("S3/strict-completion/data-directory assertion failed")
        self.check_wal(data)

    @staticmethod
    def check_wal(data):
        segments = [p.name for p in (data / "pg_wal").iterdir()
                    if re.fullmatch(r"[0-9A-Fa-f]{24}(?:\.partial)?", p.name)]
        if segments:
            raise RuntimeError("LOCAL WAL SEGMENTS PRESENT: " + ", ".join(segments))

    def run_suite(self, kind):
        directory = self.root / kind
        directory.mkdir()
        inputs = self.source / kind
        schedule = inputs / ("parallel_schedule" if kind == "regress" else "isolation_schedule")
        names = []
        for line in schedule.read_text().splitlines():
            line = line.strip()
            if line.startswith("test:"):
                names.extend(line.split()[1:])
            elif line and not line.startswith("#"):
                raise RuntimeError("unhandled schedule directive: " + line)
        candidates = {p.stem for p in (inputs / ("sql" if kind == "regress" else "specs")).iterdir()
                      if p.suffix == (".sql" if kind == "regress" else ".spec")}
        outside = sorted(candidates - set(names))
        self.say(kind + " tests outside upstream's standard schedule (NOT RUN): " + ", ".join(outside))
        (directory / "coverage.json").write_text(json.dumps({"scheduled": names,
            "outside_standard_schedule": outside}, indent=2) + "\n")
        process = None
        prefix = "s3-suite-" + uuid.uuid4().hex + "/" + kind + "/"
        (directory / "prefix.txt").write_text(prefix + "\n")
        self.say("Disposable archive (retained): s3://" + self.args.bucket + "/" + prefix)
        self.say("Later cleanup: " + shlex.join(self.aws("s3", "rm",
                 "s3://" + self.args.bucket + "/" + prefix, "--recursive")))
        try:
            data, config, socket = (directory / n for n in ("data", "config", "socket"))
            config.mkdir()
            socket.mkdir()
            code = self.command(kind + "-initdb", [Path(self.args.pg_bin) / "initdb", "-D", data,
                                "-U", "postgres", "-A", "trust", "--no-locale", "--encoding=UTF8",
                                "--data-checksums"], timeout=120)
            if code:
                raise RuntimeError("initdb failed, exit " + str(code))
            settings = dict(data_directory=str(data), hba_file=str(config / "pg_hba.conf"),
                            ident_file=str(config / "pg_ident.conf"), listen_addresses="",
                            unix_socket_directories=str(socket), port="55449", io_method="sync",
                            shared_buffers="128MB", max_connections="100", max_stack_depth="6000",
                            wal_level="replica", fsync="on", synchronous_commit="on",
                            synchronous_standby_names="", hot_standby="off", restart_after_crash="off",
                            archive_mode="off", max_prepared_transactions="2",
                            log_checkpoints="on", log_lock_waits="on",
                            log_line_prefix="%m %b[%p] %q%a ")
            settings.update({"pgrust.s3": "on", "pgrust.s3_create": "on",
                             "pgrust.memory_wal": self.args.memory_wal,
                             "pgrust.strict_synchronous_commit": "on",
                             "pgrust.s3_endpoint": self.args.endpoint, "pgrust.s3_bucket": self.args.bucket,
                             "pgrust.s3_region": self.args.region, "pgrust.s3_prefix": prefix})
            (config / "postgresql.conf").write_text("\n".join(
                k + "='" + v.replace("\\", "\\\\").replace("'", "''") + "'" for k, v in settings.items()) + "\n")
            (config / "pg_hba.conf").write_text("local all all trust\nlocal replication all trust\n")
            (config / "pg_ident.conf").touch()
            with (directory / "server.log").open("w") as log:
                process = subprocess.Popen([str(REPO / "target/debug/postgres"), "-D", str(config)],
                                           env=self.env, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
            self.say("Server log: " + str(directory / "server.log"))
            deadline = time.monotonic() + 300
            while True:
                if process.poll() is not None:
                    raise RuntimeError("server exited during startup; see " + str(directory / "server.log"))
                try:
                    if self.sql(socket, "SELECT 1") == "1":
                        break
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("S3 cluster startup timed out")
                time.sleep(.5)
            self.check_mode(socket, data, prefix)
            self.sql(socket, "CREATE TABLE s3_suite_probe (id integer); INSERT INTO s3_suite_probe VALUES (1);")
            lsn = self.sql(socket, "SELECT pg_current_wal_insert_lsn();")
            position = (int(lsn.split('/')[0], 16) << 32) | int(lsn.split('/')[1], 16)
            deadline = time.monotonic() + 30
            while True:
                self.capture(self.aws("s3api", "get-object", "--bucket", self.args.bucket,
                                      "--key", prefix + "head", str(directory / "head.json")))
                head = json.loads((directory / "head.json").read_text())
                if head["end"] >= position:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("S3 head did not cover the probe's acknowledged WAL")
                time.sleep(.5)
            self.say("S3 publication assertion passed through LSN " + lsn)

            def monitor():
                self.check_wal(data)
                if process.poll() is not None:
                    lines = (directory / "server.log").read_text(errors="replace").splitlines()
                    panic = next((line for line in reversed(lines) if "PANIC:" in line), "see server.log")
                    raise RuntimeError("pgrust stopped during suite: " + panic)

            driver = Path(self.args.pg_tests) / kind / ("pg_regress" if kind == "regress" else "pg_isolation_regress")
            code = self.command(kind + "-tests", [driver, "--bindir=" + self.args.pg_bin,
                                "--inputdir=" + str(inputs), "--outputdir=" + str(directory),
                                "--schedule=" + str(schedule), "--dlpath=" + str(inputs),
                                "--host=" + str(socket), "--port=55449", "--user=postgres",
                                "--max-concurrent-tests=20"], cwd=directory, monitor=monitor)
            self.check_mode(socket, data, prefix)
            return code
        finally:
            if process:
                stop_group(process, signal.SIGINT)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.say(kind + ": server needed forced shutdown")
                finally:
                    stop_group(process, signal.SIGKILL)
                    process.wait()
            results = directory / "regression.out"
            text = results.read_text(errors="replace") if results.exists() else ""
            completed = set(re.findall(r"(?:not )?ok\s+\d+\s+[-+]\s+(\S+)", text))
            # pg_regress TAP output is stdout; regression.out may use legacy formatting.
            driver_log = self.root / (kind + "-tests.log")
            if driver_log.exists():
                text += driver_log.read_text(errors="replace")
                completed.update(re.findall(r"(?:not )?ok\s+\d+\s+[-+]\s+(\S+)", text))
            failed = sorted(set(re.findall(r"not ok\s+\d+\s+[-+]\s+(\S+)", text)))
            (directory / "failed-tests.txt").write_text("\n".join(failed) + "\n")
            self.say(kind + " failed tests: " + (", ".join(failed) or "none reported"))
            skips = [line for line in text.splitlines() if re.search(r"#\s*SKIP\b", line, re.I)]
            if skips:
                self.say(kind + " SKIPPED results:\n" + "\n".join(skips))
                self.results[kind + "-skips"] = "INCOMPLETE: driver reported skipped tests"
            missing = [name for name in names if name not in completed]
            (directory / "not-run.txt").write_text("\n".join(missing) + "\n")
            self.say(kind + " scheduled tests without a completion result: " + (", ".join(missing) or "none"))
            self.say(kind + " failure details: " + str(directory / "regression.diffs"))
            if missing and self.results.get("build") == "PASS":
                self.results[kind + "-coverage"] = "INCOMPLETE: " + str(len(missing)) + " tests without results"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", default=os.getenv("PG_BIN", ""))
    parser.add_argument("--pg-tests", default=os.getenv("PG_TESTS", ""), help="pgxs/src/test directory")
    parser.add_argument("--sharedir", default=os.getenv("PGRUST_PGSHAREDIR", ""))
    parser.add_argument("--test-source", default=os.getenv("PG_TEST_SOURCE", ""), help="unmodified PostgreSQL src/test directory")
    parser.add_argument("--endpoint", default="http://127.0.0.1:9000")
    parser.add_argument("--bucket", default="pgrust-wal-experiments", help="existing disposable-test bucket")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--memory-wal", default="256MB", choices=["128MB", "256MB", "512MB", "1GB"])
    parser.add_argument("--timeout", type=int, default=21600, help="seconds per long-running phase (default 6 hours)")
    args = parser.parse_args()
    if not all((args.pg_bin, args.pg_tests, args.sharedir, args.test_source)):
        parser.error("run with nix develop -c python3 scripts/test_s3_wal.py, or supply all PostgreSQL paths")
    os.umask(0o077)
    run = Run(args)
    for name in ("workspace", "waiter-isolated-clock", "build", "sql-prerequisites", "regress", "isolation"):
        run.results[name] = "NOT RUN"
    try:
        run.say("Scope: native default-feature Rust workspace under its normal test contract; standard upstream SQL/isolation schedules.")
        run.say("Ignored Rust entries are reported separately; they are not all safe to run together with --include-ignored.")
        run.say("No overlays, expected-result edits, simulation/wasm builds, contrib/TAP suites, or proof/fuzz workspaces.")
        run.say("Rust unit tests retain their own fixtures; only the two server suites force S3 mode.")
        run.say("Git HEAD: " + run.capture(["git", "rev-parse", "HEAD"]))
        run.say("Working tree:\n" + run.capture(["git", "status", "--short"]))
        if os.getenv("CARGO_BUILD_TARGET") or "pgrust_sim" in os.getenv("RUSTFLAGS", ""):
            raise RuntimeError("unset CARGO_BUILD_TARGET and simulation RUSTFLAGS for this native run")
        common = ["--locked", "--target-dir", str(REPO / "target"),
                  "--message-format=json", "--color=never"]
        run.phase("workspace", lambda: run.workspace(common))
        run.phase("waiter-isolated-clock", lambda: run.command("waiter-isolated-clock",
                  ["cargo", "test", "-p", "waiter", "--lib", *common, "--", "--ignored",
                   "--exact", "tests::virtual_time_drives_timeouts"]))
        run.phase("build", lambda: run.command("build", ["cargo", "build", *common,
                  "-p", "main_main", "--bin", "postgres"]))
        run.phase("sql-prerequisites", run.prerequisites)
        for kind in ("regress", "isolation"):
            if run.results["build"] == "PASS" and run.results["sql-prerequisites"] == "PASS":
                run.phase(kind, lambda kind=kind: run.run_suite(kind))
            else:
                run.results[kind] = "BLOCKED: native build or SQL prerequisites failed; entire schedule NOT RUN"
    except KeyboardInterrupt:
        run.results["interrupted"] = "INTERRUPTED; unfinished phases are NOT RUN"
    except Exception as error:
        run.results["runner"] = "FAIL: " + str(error)
    finally:
        run.save_summary()
        run.say("\nFINAL RESULTS\n" + json.dumps(run.results, indent=2))
        run.say("Combined log: " + str(run.root / "run.log"))
        run.say("All local artifacts and unique S3 prefixes retained; no existing databases or bucket objects deleted.")
    return 0 if all(status == "PASS" for status in run.results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
