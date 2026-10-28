#!/usr/bin/env python3
"""Build/run isolated Core processes against a loopback AMQP protocol stub.
No installation, working configuration, service restart or RabbitMQ required.
Run in the development container with its installed, compatible libfreeswitch.
"""
import argparse
import os
from pathlib import Path
import socket
import struct
import time
import subprocess
import threading


def frame(channel, cls, method, payload=b""):
    body = struct.pack("!HH", cls, method) + payload
    return struct.pack("!BHI", 1, channel, len(body)) + body + b"\xce"


def read_exact(conn, size):
    data = b""
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError
        data += part
    return data


def read_frame(conn):
    kind, channel, size = struct.unpack("!BHI", read_exact(conn, 7))
    payload = read_exact(conn, size)
    assert read_exact(conn, 1) == b"\xce"
    return kind, channel, payload


class Broker:
    def __init__(self, stage, ready):
        self.stage, self.ready = stage, ready
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.arrivals = 0
        self.errors = []
        self.declares = {}
        self.retry_gaps = []
        self.sockets, self.threads = [], []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def mark_ready(self):
        with self.lock:
            self.arrivals += 1
            if self.arrivals >= 2:
                self.ready.touch()

    def accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(3)
            self.sockets.append(conn)
            thread = threading.Thread(target=self.client, args=(conn,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def client(self, conn):
        try:
            assert read_exact(conn, 8) == b"AMQP\x00\x00\x09\x01"
            if self.stage == "handshake":
                self.mark_ready()
                self.stop.wait(15)
                return
            conn.sendall(frame(0, 10, 10, b"\x00\x09" + struct.pack("!I", 0) + struct.pack("!I", 5) + b"PLAIN" + struct.pack("!I", 5) + b"en_US"))
            _, _, start_ok = read_frame(conn)
            table_length = struct.unpack("!I", start_ok[4:8])[0]
            cursor, keys = 8, []
            while cursor < 8 + table_length:
                length = start_ok[cursor]
                cursor += 1
                keys.append(start_ok[cursor:cursor + length])
                cursor += length
                kind = start_ok[cursor:cursor + 1]
                cursor += 1
                if kind in (b"S", b"x", b"F", b"A"):
                    length = struct.unpack("!I", start_ok[cursor:cursor + 4])[0]
                    cursor += 4 + length
                else:
                    widths = {b"t": 1, b"b": 1, b"B": 1, b"U": 2, b"u": 2,
                              b"I": 4, b"i": 4, b"f": 4, b"L": 8, b"l": 8,
                              b"T": 8, b"d": 8, b"D": 5, b"V": 0}
                    assert kind in widths, kind
                    cursor += widths[kind]
            own_keys = [key for key in keys if key.startswith(b"x_")]
            assert len(own_keys) == len(set(own_keys)) == 5, own_keys
            conn.sendall(frame(0, 10, 30, struct.pack("!HIH", 0, 131072, 0)))
            read_frame(conn)  # tune-ok
            read_frame(conn)  # connection.open
            conn.sendall(frame(0, 10, 41, b"\x00"))
            _, channel, payload = read_frame(conn)
            assert payload[:4] == struct.pack("!HH", 20, 10)
            conn.sendall(frame(channel, 20, 11, struct.pack("!I", 0)))
            _, channel, payload = read_frame(conn)
            assert payload[:4] == struct.pack("!HH", 40, 10)
            if self.stage == "declare-recovery":
                length = payload[6]
                exchange = payload[7:7 + length]
                with self.lock:
                    previous = self.declares.get(exchange)
                    self.declares[exchange] = time.monotonic()
                    if previous is not None:
                        self.retry_gaps.append(time.monotonic() - previous)
                if previous is None:
                    conn.sendall(frame(channel, 20, 40, struct.pack("!H", 406) + b"\x05probe" + struct.pack("!HH", 40, 10)))
                    return
            if self.stage == "rpc":
                self.mark_ready()
                self.stop.wait(15)
                return
            conn.sendall(frame(channel, 40, 11))
            if self.stage == "legacy-commands":
                _, channel, payload = read_frame(conn)
                assert payload[:4] == struct.pack("!HH", 50, 10)
                queue = b"\x0dlocal-command"
                conn.sendall(frame(channel, 50, 11, queue + struct.pack("!II", 0, 0)))
                _, channel, payload = read_frame(conn)
                assert payload[:4] == struct.pack("!HH", 50, 20)
                conn.sendall(frame(channel, 50, 21))
                _, channel, payload = read_frame(conn)
                assert payload[:4] == struct.pack("!HH", 60, 20)
                conn.sendall(frame(channel, 60, 21, b"\x03tag"))
                for tag, body in enumerate([b"uuid_exists mod-amqp-local-test-missing-channel",
                                           b"bgapi originate error/mod-amqp-local-test &park()"], 1):
                    method = b"\x03tag" + struct.pack("!QB", tag, 0) + b"\x00\x00"
                    header = struct.pack("!HHQH", 60, 0, len(body), 0)
                    conn.sendall(frame(channel, 60, 60, method) +
                                 struct.pack("!BHI", 2, channel, len(header)) + header + b"\xce" +
                                 struct.pack("!BHI", 3, channel, len(body)) + body + b"\xce")
                self.arrivals += 1
                self.ready.touch()
                self.stop.wait(15)
                return
            self.mark_ready()
            # Stop reading completely: publisher must eventually fill the TCP socket.
            self.stop.wait(15)
        except (EOFError, ConnectionError, OSError):
            # EOF is expected when stop interrupts handshake or a failed connection.
            pass
        except Exception as exc:
            self.errors.append(repr(exc))
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        for conn in self.sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(1)
        for thread in self.threads:
            thread.join(1)


def config(port, recovery=False):
    interval = 200 if recovery else 60000
    log_reconnect = '' if recovery else '<param name="reconnect_interval_ms" value="60000"/>'
    connection = f"""<connections><connection name="probe"><param name="hostname" value="127.0.0.1"/>
      <param name="port" value="{port}"/><param name="connect-timeout-ms" value="1000"/>
      <param name="rpc-timeout-ms" value="1000"/></connection></connections>"""
    return f"""<document type="freeswitch/xml"><section name="configuration">
      <configuration name="modules.conf"><modules/></configuration>
      <configuration name="timezones.conf"><timezones><zone name="GMT" value="GMT0"/></timezones></configuration>
      <configuration name="amqp.conf"><producers><profile name="probe-events">
      <params><param name="event_filter" value="DTMF"/><param name="reconnect_interval_ms" value="{interval}"/><param name="exchange-name" value="probe-events"/></params>
      {connection}</profile></producers><logging><profile name="probe-log">
      <params><param name="log-levels" value="err"/>{log_reconnect}<param name="exchange-name" value="probe-log"/></params>
      {connection}</profile></logging><commands/>
      </configuration></section></document>"""


def legacy_config(port):
    return f"""<document type="freeswitch/xml"><section name="configuration">
      <configuration name="modules.conf"><modules/></configuration>
      <configuration name="timezones.conf"><timezones><zone name="GMT" value="GMT0"/></timezones></configuration>
      <configuration name="amqp.conf"><commands><profile name="local-command"><params>
      <param name="exchange-name" value="local-commands"/><param name="queue-name" value="local-command"/>
      <param name="binding_key" value="local-test"/><param name="reconnect_interval_ms" value="1000"/>
      </params><connections><connection name="local"><param name="hostname" value="127.0.0.1"/>
      <param name="port" value="{port}"/><param name="connect-timeout-ms" value="1000"/>
      <param name="rpc-timeout-ms" value="1000"/></connection></connections></profile></commands>
      </configuration></section></document>"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--sanitizer", choices=["address,undefined", "thread"])
    parser.add_argument("--case", action="append", default=[], help="Run only the named scenario(s)")
    parser.add_argument("--gdb", action="store_true", help="Capture the isolated child's failure backtrace")
    parser.add_argument("--legacy-commands", action="store_true", help="Probe trusted local legacy console commands")
    parser.add_argument("--core-bgapi", action="store_true", help="Reproduce Core bgapi teardown without loading mod_amqp")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    module = Path(__file__).resolve().parent.parent
    root = module.parents[3]
    core = Path(os.environ.get("MOD_AMQP_CORE_LIBDIR", "/usr/local/freeswitch/lib"))
    cc = os.environ.get("CC", "cc")
    flags = ["-DHAVE_CONFIG_H", "-DSWITCH_API_VISIBILITY=1", "-DCJSON_API_VISIBILITY=1", "-DHAVE_VISIBILITY=1", "-DHAVE_OPENSSL", "-Wall", "-Werror", "-O1", "-g", "-fno-omit-frame-pointer"]
    for directory in [root / "src/include", root / "libs/esl/src/include", root / "libs/xmlrpc-c", root / "libs/libteletone/src", module]:
        flags += ["-I", str(directory)]
    if args.sanitizer:
        flags += [f"-fsanitize={args.sanitizer}"]
    # Keep rabbitmq-c in the interposer's global lookup scope even when the
    # linker sees only its own amqp_basic_publish definition (--as-needed).
    libs = [str(core / "libfreeswitch.so"), f"-Wl,-rpath,{core}", "-Wl,--no-as-needed", "-lrabbitmq", "-Wl,--as-needed", "-ldl", "-lpthread", "-lssl", "-lcrypto"]
    binary_dir = output / "bin"
    binary_dir.mkdir(exist_ok=True)
    commands = [
        [cc, *flags, "-fPIC", "-shared", *map(str, sorted(module.glob("*.c"))), *libs, "-o", str(binary_dir / "mod_amqp.so")],
        [cc, *flags, "-fPIC", "-shared", str(module / "test/lifecycle_probe_interposer.c"), *libs, "-o", str(binary_dir / "interposer.so")],
        [cc, *flags, str(module / "test/lifecycle_probe.c"), *libs, "-o", str(binary_dir / "probe")],
    ]
    with (output / "build.log").open("w") as log:
        for command in commands:
            subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    env = dict(os.environ, AMQP_PROBE_MODULE=str(binary_dir), ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1", TSAN_OPTIONS="halt_on_error=1")
    preload = [str(binary_dir / "interposer.so")]
    if args.sanitizer:
        library = "libasan.so" if args.sanitizer.startswith("address") else "libtsan.so"
        preload.insert(0, subprocess.check_output([cc, f"-print-file-name={library}"], text=True).strip())
    env["LD_PRELOAD"] = ":".join(preload)
    failures = []
    scenarios = [
        ("unload-handshake", "unload", "handshake"), ("unload-rpc", "unload", "rpc"),
        ("blocked-publish", "publish", "queue"), ("process-handshake", "process", "handshake"),
        ("process-rpc", "process", "rpc"), ("process-queue", "process", "queue"),
        ("process-publish", "process-publish", "queue"),
        ("declare-recovery", "unload", "declare-recovery"),
        ("reload-unload-race", "race", "handshake"), ("load-unload-cycle", "cycle", "handshake"),
    ]
    if args.legacy_commands:
        scenarios = [("legacy-command-unload", "unload", "legacy-commands"),
                     ("legacy-command-process", "process", "legacy-commands")]
    if args.core_bgapi:
        scenarios = [("core-bgapi", "core-bgapi", "legacy-commands")]
    for label, mode, stage in scenarios:
        if args.case and label not in args.case:
            continue
        fixture = output / label
        fixture.mkdir(exist_ok=True)
        ready = fixture / "ready"
        ready.unlink(missing_ok=True)
        broker = Broker(stage, ready)
        try:
            (fixture / "freeswitch.xml").write_text(legacy_config(broker.port) if args.legacy_commands else config(broker.port, stage == "declare-recovery"))
            with (fixture / "probe.log").open("w") as log:
                command = [str(binary_dir / "probe"), mode]
                if args.gdb:
                    command = ["gdb", "-q", "-batch", "--return-child-result", "-ex", "run", "-ex", "thread apply all bt 10", "--args", *command]
                child_env = dict(env, AMQP_PROBE_ROOT=str(fixture), AMQP_PROBE_READY=str(ready),
                        AMQP_PROBE_STATE="ready" if stage in ("queue", "declare-recovery") else "connecting",
                        AMQP_PROBE_RECOVERY="true" if stage == "declare-recovery" else "false")
                if args.legacy_commands or args.core_bgapi:
                    child_env["AMQP_PROBE_LEGACY_COMMAND"] = "true"
                result = subprocess.run(command, cwd=root, env=child_env,
                    stdout=log, stderr=subprocess.STDOUT, timeout=20)
            if stage == "declare-recovery" and (len(broker.retry_gaps) != 2 or min(broker.retry_gaps) < 0.18):
                broker.errors.append(f"invalid reconnect delays: {broker.retry_gaps}")
            if result.returncode or broker.errors:
                failures.append(label)
            print(f"{label}: exit={result.returncode} connections={broker.arrivals} errors={broker.errors}", flush=True)
        except subprocess.TimeoutExpired:
            failures.append(label)
            print(f"{label}: TIMEOUT", flush=True)
        finally:
            broker.close()
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
