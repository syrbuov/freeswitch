# Изолированные команды проверки hardening

Все команды запускались в контейнере freeswitch-dev из /usr/src/freeswitch. Они не выполняют install, reload/unload работающего сервиса или изменение рабочего XML.

~~~sh
cd /usr/src/freeswitch/src/mod/event_handlers/mod_amqp
make -j2 CFLAGS="-O1 -g -Wall -Werror" mod_amqp.la check \
  mod_amqp_la_LIBADD="-L/usr/local/freeswitch/lib -lfreeswitch" \
  mod_amqp_la_LDFLAGS="-avoid-version -module -no-undefined -shared -lrabbitmq -Wl,-z,defs -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_filter_engine_LDADD=/usr/local/freeswitch/lib/libfreeswitch.so \
  test_test_filter_engine_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_producer_lifecycle_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq" \
  test_test_producer_lifecycle_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_producer_integration_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq" \
  test_test_producer_integration_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib -ldl"
~~~

Exit 0; вывод: check-permanent-v2.log. Установленная libfreeswitch имеет SHA-256 85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145.

~~~sh
cd /usr/src/freeswitch
sh docs/mod_amqp/hardening-artifacts/check-deps.sh
cd src/mod/event_handlers/mod_amqp
MOD_AMQP_SANITIZER_TEST=test_filter_engine sh test/run_filter_engine_sanitizers.sh /usr/src/freeswitch/docs/mod_amqp/hardening-artifacts/sanitizers-engine-policy-final
MOD_AMQP_SANITIZER_TEST=test_producer_integration sh test/run_filter_engine_sanitizers.sh /usr/src/freeswitch/docs/mod_amqp/hardening-artifacts/sanitizers-policy-final
~~~

Dependency probe exit 0. Engine sanitizer exit 0. Integration sanitizer exit 1 из-за ASan; TSan в том же прогоне прошёл.

Изолированные loader probes выполнялись по одному в отдельных процессах после сборки harness/interposer с -Wall -Werror:

~~~sh
cd /usr/src/freeswitch
for scenario in normal initial-clean initial-retained; do
  LD_PRELOAD=docs/mod_amqp/hardening-artifacts/loader-fault-interposer.so \
    timeout 45s docs/mod_amqp/hardening-artifacts/loader-fault-main "$scenario"
done
~~~

Каждый сценарий exit 0; отдельные журналы loader-*-v3.log.
