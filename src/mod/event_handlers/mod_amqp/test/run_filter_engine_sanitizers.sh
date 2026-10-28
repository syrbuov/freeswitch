#!/bin/sh
# Isolated test binaries only. Integration uses full Core eventing; standalone
# engine may use minimal Core. Does not install modules or build Core.
set -eu

amqp_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
amqp_source_root=$(CDPATH= cd -- "$amqp_dir/../../../.." && pwd)
amqp_output_dir=${1:-$(mktemp -d /tmp/mod-amqp-filter-sanitizers.XXXXXX)}
amqp_core_libdir=${2:-/usr/local/freeswitch/lib}
mkdir -p "$amqp_output_dir"
amqp_output_dir=$(CDPATH= cd -- "$amqp_output_dir" && pwd)
amqp_core_libdir=$(CDPATH= cd -- "$amqp_core_libdir" && pwd)
amqp_failed=0
amqp_test=${MOD_AMQP_SANITIZER_TEST:-test_filter_engine}
case "$amqp_test" in
	test_filter_engine) ;;
	test_producer_integration) ;;
	*) printf "Unsupported test: %s\n" "$amqp_test" >&2; exit 2 ;;
esac

for amqp_sanitizer in address,undefined thread; do
	amqp_binary="$amqp_output_dir/${amqp_test}_$amqp_sanitizer"
	amqp_proxy_dir="$amqp_output_dir/$amqp_sanitizer"
	mkdir -p "$amqp_proxy_dir"
	set --
	if [ "$amqp_test" = test_producer_integration ]; then
		set -- "$amqp_dir/mod_amqp_connection.c" "$amqp_dir/mod_amqp_filter_parser.c" \
			"$amqp_dir/mod_amqp_filter_compiler.c" "$amqp_dir/mod_amqp_filter_matcher.c"
		if ! "${CC:-cc}" -DHAVE_CONFIG_H -I"$amqp_source_root/src/include" \
			-I"$amqp_source_root/libs/esl/src/include" -I"$amqp_source_root/libs/xmlrpc-c" \
			-I"$amqp_source_root/libs/libteletone/src" \
			-DSWITCH_API_VISIBILITY=1 -DCJSON_API_VISIBILITY=1 -DHAVE_VISIBILITY=1 -DHAVE_OPENSSL \
			-Wall -Werror \
			-g -O1 -fPIC -shared "-fsanitize=$amqp_sanitizer" \
			"$amqp_dir/test/api_reply_proxy.c" "$amqp_core_libdir/libfreeswitch.so" \
			"-Wl,-rpath,$amqp_core_libdir" -o "$amqp_proxy_dir/mod_amqp_api_reply_proxy.so" \
			> "$amqp_binary.proxy.build.log" 2>&1; then
			printf '%s: PROXY BUILD FAILED (%s.proxy.build.log)\n' "$amqp_sanitizer" "$amqp_binary"
			amqp_failed=1
			continue
		fi
	fi
	if "${CC:-cc}" -DHAVE_CONFIG_H -I"$amqp_dir" -I"$amqp_source_root/src/include" \
		-I"$amqp_source_root/libs/esl/src/include" -I"$amqp_source_root/libs/xmlrpc-c" \
		-I"$amqp_source_root/libs/libteletone/src" \
		-DSWITCH_API_VISIBILITY=1 -DCJSON_API_VISIBILITY=1 -DHAVE_VISIBILITY=1 -DHAVE_OPENSSL \
		-Wall -Werror -Wno-unused-result -Wno-misleading-indentation -std=c99 -pedantic \
		-Wdeclaration-after-statement -g -O1 -fno-omit-frame-pointer "-fsanitize=$amqp_sanitizer" \
		"-DMOD_AMQP_API_PROXY_DIR=\"$amqp_proxy_dir\"" \
		"-DSWITCH_TEST_BASE_DIR_FOR_CONF=\"$amqp_dir/test\"" \
		"-DSWITCH_TEST_BASE_DIR_OVERRIDE=\"$amqp_dir/test\"" \
		"$amqp_dir/test/$amqp_test.c" "$@" "$amqp_core_libdir/libfreeswitch.so" -lrabbitmq \
		"-Wl,-rpath,$amqp_core_libdir" -lssl -lcrypto -lpthread -ldl -o "$amqp_binary" \
		> "$amqp_binary.build.log" 2>&1; then
		if MOD_AMQP_FILTER_TEST_MINIMAL=1 ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 TSAN_OPTIONS=halt_on_error=1 \
			timeout 90s "$amqp_binary" > "$amqp_binary.log" 2>&1; then
			printf '%s: PASS (%s.log)\n' "$amqp_sanitizer" "$amqp_binary"
		else
			amqp_status=$?
			printf '%s: FAIL, exit %s (%s.log)\n' "$amqp_sanitizer" "$amqp_status" "$amqp_binary"
			amqp_failed=1
		fi
	else
		printf '%s: BUILD FAILED (%s.build.log)\n' "$amqp_sanitizer" "$amqp_binary"
		amqp_failed=1
	fi
done
exit "$amqp_failed"
