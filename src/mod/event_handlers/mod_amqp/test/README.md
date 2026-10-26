# Producer lifecycle tests

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
The FST driver initializes core explicitly to avoid requiring a soft timer.

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
