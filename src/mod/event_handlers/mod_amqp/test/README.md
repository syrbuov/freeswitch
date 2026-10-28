Profile diagnostics and TCP recovery (2026-10-28): `amqp profiles` returns a
JSON snapshot of workers, connection phase, queues and counters; it rejects a
busy lifecycle without waiting. Counters reset with the profile generation;
`publish_ok` means local publish success, not broker confirmation. See the
[diagnostics report](../../../../../docs/mod_amqp/filter-engine-profile-diagnostics.md).
DNS/TLS work is deferred. The loopback runner now also covers recovery from a
rejected exchange declaration and verifies the default logging reconnect delay.

Current lifecycle validation (2026-10-28): command profiles are disabled;
producer/logging use interruptible waits and socket cancellation. Normal load
is unloadable and participates in Core process shutdown. See
[the current report](../../../../../docs/mod_amqp/filter-engine-lifecycle-without-core.md)
for the supported management context and remaining Core/DNS/TLS limits.

The standalone network probes do not install a module or require RabbitMQ:

```sh
python3 test/run_lifecycle_probes.py /tmp/mod-amqp-lifecycle-probes
python3 test/run_lifecycle_probes.py /tmp/mod-amqp-lifecycle-probes-asan --sanitizer address,undefined
python3 test/run_lifecycle_probes.py /tmp/mod-amqp-lifecycle-probes-tsan --sanitizer thread
```

# mod_amqp tests

## Producer lifecycle

These tests use `switch_test.h` and the real FreeSWITCH event engine, bindings,
queues, memory pools and thread joins. A joinable test worker replaces the
network sender and observes the production synchronized stop flag; RabbitMQ
is not required. Fault injection is confined to the test translation unit,
which includes `mod_amqp_producer.c`. The production build has no test hooks.

After configuring FreeSWITCH, run from the repository root:

```sh
make -C src/mod/event_handlers/mod_amqp check
```

Automake registers the executable as `test/test_producer_lifecycle`. The fixture
loads no dynamic modules and supplies an empty `amqp.conf` for reload checks.
The full event engine is required: `SCF_MINIMAL` would skip event delivery.
The drivers point `mod_dir` at `test/conf`: an empty modules list alone would
make Core scan the installed module directory. Full initialization still uses
built-in Core modules, including its soft timer.

The suite covers independent bindings, legacy overlap/default/empty/subclass
behavior, duplicate names, ownership of hash entries, partial bind failures,
queue/hash/thread creation failures, retry after unbind/join failures, callback
and sender barriers, concurrent reload rejection, repeated reload and rejection
of reload originating in a command worker, reentrant reload, individual shutdown
and the `NOUNLOAD` result when a sender could not be joined. Mutex/queue/thread
creation failures intentionally publish unusable output handles, checking that
only successfully created resources become owned by the profile.

On 2026-10-26 the suite was rebuilt and passed **18/18 cases** in the Docker
development container, including a run linked explicitly against the installed
fresh-image libfreeswitch. See [diagnostic results](../../../../../docs/mod_amqp/docker-segfault-diagnosis.md)
for commands and the cached-Core mismatch. ASan/UBSan and TSan with an
instrumented libfreeswitch have not been run. The suite
does not validate RabbitMQ I/O, real sender reconnect/timeout behavior, arbitrary
third-party event callbacks invoking reload, or full command/logging teardown.

## Standalone Filter Engine

`test/test_filter_engine.c` includes the three production engine sources with
test-local malloc/calloc accounting, allocation failure injection and guards
against binding, thread, queue, serialization and hash management calls.
Production code contains no test hooks. XML, event creation and headers use
real FreeSWITCH APIs. The engine has no dependency on producer globals or AMQP.

There are 19 test cases, including exact event spellings (`CUSTOM` and
`SWITCH_EVENT_CUSTOM`), strict XML, OR/AND, normalization and subscriptions,
canonical event fields, repeated headers and arrays, empty/missing values,
XML/DTO lifetime, limits, allocation failures, event immutability, allocation-free
matching, and eight concurrent readers (20,000 matches each).

The regular run initializes full Core. The test-only environment variable
`MOD_AMQP_FILTER_TEST_MINIMAL=1` selects minimal Core: all 19 tests and real
reader threads still run, but event delivery and unrelated Core subsystems are
not needed. This isolates the sanitizer checks; producer lifecycle tests still
require full Core.

In a configured build whose cached Core differs from the installed Core, use
explicit linkage rather than relying on the build-tree `.la`:

```sh
cd /usr/src/freeswitch/src/mod/event_handlers/mod_amqp
make -j2 mod_amqp.la check \
  mod_amqp_la_LIBADD="-L/usr/local/freeswitch/lib -lfreeswitch" \
  mod_amqp_la_LDFLAGS="-avoid-version -module -no-undefined -shared -lrabbitmq -Wl,-z,defs -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_filter_engine_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so" \
  test_test_filter_engine_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_producer_lifecycle_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq" \
  test_test_producer_lifecycle_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib"
```

The sanitizer helper compiles isolated binaries under `/tmp`, links the
explicitly selected installed Core, and runs both ASan/UBSan (with leak
detection) and TSan. It requires a configured source tree, a compatible Core,
GCC-compatible sanitizer flags, and `timeout`:

```sh
sh test/run_filter_engine_sanitizers.sh /tmp/mod-amqp-stage2-sanitizers /usr/local/freeswitch/lib
```

Neither command installs anything or reloads the running module. Core itself
is not instrumented by the helper. See the [stage 2 report](../../../../../docs/mod_amqp/filter-engine-stage2.md)
for successful runs and the separate sanitizer failures with full Core.

## Producer integration (stage 3)

`test/test_producer_integration.c` selects 24 producer cases using the shared
lifecycle fixture. It includes the production producer, configuration, module,
command and logging code with test-local wrappers; connection settings and
engine sources are compiled separately. It exercises real Core bindings/unbind,
JSON, queues and logger delivery, including callback/JSON/enqueue counters.
Producer workers use the synchronized stop accessor. Adjacent workers exit
without network I/O; no RabbitMQ server is contacted by these workers.

Coverage includes mode selection and legacy overlaps, unique rules subscriptions,
rejection before allocation/JSON, whole-set preparation and activation failure
cleanup, retained engines and reader/sender barriers, API error propagation,
logger rebinding, all concrete subscriptions, 1024 rules, and concurrent queue
overflow. The original 18 lifecycle and 19 engine cases remain separate suites.

Five additional cases exercise the `amqp` API reply through the real
`mod_event_socket` listener and Core `switch_api_execute()` in the isolated
integration process. A test-only proxy DSO registers the executable's
`amqp_reload()` function in Core; it does not replace the handler. ESL binds
only to `127.0.0.1:28741` with the password in `test/conf/freeswitch.xml`.
The suite needs an installed `mod_event_socket.so` compatible with the selected
Core. It tests success, invalid mode, busy lifecycle mutex, teardown failure
and activation failure. The production service and its configuration are not
loaded by this fixture.

```sh
MOD_AMQP_SANITIZER_TEST=test_producer_integration \
  sh test/run_filter_engine_sanitizers.sh /tmp/mod-amqp-stage3-sanitizers /usr/local/freeswitch/lib
```

Integration always requires full eventing and asserts `switch_event_running()`.
It does not select minimal Core. The helper instruments module/test sources,
not the installed Core or `mod_event_socket` DSO. ASan/UBSan/LSan and TSan
passed 29/29 with exit 0 on 2026-10-27; real AMQP network workers and live
installation of the new module remain untested. See the
[stage 3 report](../../../../../docs/mod_amqp/filter-engine-stage3.md) for exact
commands, limitations and the corrected interpretation of earlier fixture runs.
