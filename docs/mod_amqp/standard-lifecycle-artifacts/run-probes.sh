#!/bin/sh
# Run inside the isolated freeswitch-dev container. Never installs a module.
set -eu
amqp_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
amqp_probe="$amqp_root/docs/mod_amqp/standard-lifecycle-artifacts"
amqp_src="$amqp_root/src/mod/event_handlers/mod_amqp"
mkdir -p "$amqp_probe/nonpermanent-src" "$amqp_probe/nonpermanent-bin"
cp "$amqp_src"/*.c "$amqp_src"/*.h "$amqp_probe/nonpermanent-src/"
python3 - "$amqp_probe/nonpermanent-src/mod_amqp.c" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text()
old='/* Core marks NOUNLOAD as permanent before publishing registry/interfaces. */\n\treturn SWITCH_STATUS_NOUNLOAD;'
assert s.count(old)==1
p.write_text(s.replace(old,'/* Probe-only: ordinary load. Production source remains unchanged. */\n\treturn SWITCH_STATUS_SUCCESS;'))
PY
cd "$amqp_root"
amqp_flags="-DHAVE_CONFIG_H -I src/include -I libs/esl/src/include -I libs/xmlrpc-c -I libs/libteletone/src -DSWITCH_API_VISIBILITY=1 -DCJSON_API_VISIBILITY=1 -DHAVE_VISIBILITY=1 -DHAVE_OPENSSL -Wall -Werror"
# shellcheck disable=SC2086
cc $amqp_flags -I "$amqp_probe/nonpermanent-src" -I /usr/local/include/rabbitmq-c -O1 -g -fPIC -shared "$amqp_probe"/nonpermanent-src/*.c /usr/local/freeswitch/lib/libfreeswitch.so -Wl,-rpath,/usr/local/freeswitch/lib -Wl,-z,defs -lrabbitmq -o "$amqp_probe/nonpermanent-bin/mod_amqp.so"
# shellcheck disable=SC2086
cc $amqp_flags -std=c11 -fPIC -shared "$amqp_probe/forced-busy-interposer.c" -ldl -lpthread -o "$amqp_probe/forced-busy-interposer.so"
for amqp_main in forced-busy-main standard-cycle-main; do
  # shellcheck disable=SC2086
  cc $amqp_flags -std=c99 -g -O1 \
    -DAMQP_PROBE_FIXTURE_ROOT="\"$amqp_root/docs/mod_amqp/acceptance-artifacts\"" \
    -DAMQP_PROBE_MODULE_DIR="\"$amqp_probe/nonpermanent-bin\"" \
    "$amqp_probe/$amqp_main.c" /usr/local/freeswitch/lib/libfreeswitch.so \
    -Wl,-rpath,/usr/local/freeswitch/lib -lssl -lcrypto -lrabbitmq -ldl -lpthread -o "$amqp_probe/$amqp_main"
done
timeout 60s "$amqp_probe/standard-cycle-main" > "$amqp_probe/standard-cycle.log" 2>&1
LD_PRELOAD="$amqp_probe/forced-busy-interposer.so" timeout 60s "$amqp_probe/forced-busy-main" > "$amqp_probe/forced-busy.log" 2>&1
cat "$amqp_probe/standard-cycle.log" "$amqp_probe/forced-busy.log"
