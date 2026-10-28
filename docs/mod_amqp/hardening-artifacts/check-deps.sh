#!/bin/sh
# Run inside the development container from the mod_amqp build directory.
# Changes only mtimes of inputs; a trap restores them after every probe.
set -eu
artifact_dir=/usr/src/freeswitch/docs/mod_amqp/hardening-artifacts
make_test() {
	make -j2 "$1" \
		mod_amqp_la_LIBADD='-L/usr/local/freeswitch/lib -lfreeswitch' \
		mod_amqp_la_LDFLAGS='-avoid-version -module -no-undefined -shared -lrabbitmq -Wl,-z,defs -Wl,-rpath,/usr/local/freeswitch/lib' \
		test_test_filter_engine_LDADD=/usr/local/freeswitch/lib/libfreeswitch.so \
		test_test_filter_engine_LDFLAGS='-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib' \
		test_test_producer_lifecycle_LDADD='/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq' \
		test_test_producer_lifecycle_LDFLAGS='-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib' \
		test_test_producer_integration_LDADD='/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq' \
		test_test_producer_integration_LDFLAGS='-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib -ldl' \
		CFLAGS='-O1 -g -Wall -Werror'
}
probe() {
	name=$1 input=$2 target=$3 object=$4
	ref="$artifact_dir/.mtime-$name"
	log="$artifact_dir/dependency-$name.log"
	touch -r "$input" "$ref"
	before=$(sha256sum "$input" | cut -d' ' -f1)
	trap 'touch -r "$ref" "$input"; rm -f "$ref"' EXIT HUP INT TERM
	sleep 1
	touch "$input"
	make_test "$target" > "$log" 2>&1
	if ! grep -F "  CC       $object" "$log" >/dev/null; then
		cat "$log"; echo "missing recompile: $name" >&2; exit 1
	fi
	if ! grep -F '  CCLD     ' "$log" >/dev/null; then
		cat "$log"; echo "missing relink: $name" >&2; exit 1
	fi
	touch -r "$ref" "$input"
	rm -f "$ref"
	trap - EXIT HUP INT TERM
	after=$(sha256sum "$input" | cut -d' ' -f1)
	[ "$before" = "$after" ] || { echo "content changed: $input" >&2; exit 1; }
	echo "$name: rebuilt object and linked target; SHA-256 unchanged"
}
make_test test/test_filter_engine > "$artifact_dir/dependency-noop-before.log" 2>&1
probe production-layout mod_amqp.h mod_amqp.la mod_amqp_la-mod_amqp_producer.lo
probe engine mod_amqp_filter_parser.c test/test_filter_engine test/test_filter_engine-test_filter_engine.o
probe lifecycle mod_amqp_producer.c test/test_producer_lifecycle test/test_producer_lifecycle-test_producer_lifecycle.o
probe integration mod_amqp.c test/test_producer_integration test/test_producer_integration-test_producer_integration.o
probe helper test/worker_loop_cases.h test/test_producer_integration test/test_producer_integration-test_producer_integration.o
probe proxy test/api_reply_proxy.c test/mod_amqp_api_reply_proxy.la test/mod_amqp_api_reply_proxy_la-api_reply_proxy.lo
make_test test/test_producer_integration > "$artifact_dir/dependency-proxy-consumer.log" 2>&1
grep -F '  CCLD     test/test_producer_integration' "$artifact_dir/dependency-proxy-consumer.log" >/dev/null
make_test test/test_filter_engine > "$artifact_dir/dependency-noop-engine.log" 2>&1
make_test mod_amqp.la > "$artifact_dir/dependency-noop-module.log" 2>&1
make_test test/test_producer_lifecycle > "$artifact_dir/dependency-noop-lifecycle.log" 2>&1
make_test test/test_producer_integration > "$artifact_dir/dependency-noop-integration.log" 2>&1
if grep -E '  (CC|CCLD) ' "$artifact_dir/dependency-noop-engine.log" \
	"$artifact_dir/dependency-noop-module.log" \
	"$artifact_dir/dependency-noop-lifecycle.log" \
	"$artifact_dir/dependency-noop-integration.log" >/dev/null; then
	echo 'unchanged tree unexpectedly rebuilt' >&2; exit 1
fi
echo 'unchanged tree: no compilation or linking'
