# mod_amqp: однозначный ответ API `amqp` при reload

Дата проверки: 27 октября 2026 года. Исходный HEAD:
`7dc0a00e84a1be2db5d999b2b5b556eae819d174`, ветка
`codex/mod-amqp-filter-engine-stage3`. До изменений tracked-файлы были чистыми;
в дереве уже находились неотслеживаемые `.vscode/tasks.json`, артефакты `build/`,
несколько сторонних каталогов модулей и тестовые бинарники. Они сохранены.
Применимых `AGENTS.md` в родительских каталогах, `docs/mod_amqp` и каталоге
модуля/тестов не найдено. Изучены [отчёт этапа 3](filter-engine-stage3.md) и
[runtime-отчёт](filter-engine-stage3-runtime.md).

## Причина проблемы и контракт

Ранее [`amqp_reload()`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L47)
возвращал результат `mod_amqp_do_config(SWITCH_TRUE)` без записи в stream.
Успех оставлял пустой ответ. При ошибке
[`switch_api_execute()`](../../src/switch_loadable_module.c#L2933)
дописывает `COMMAND RETURNED ERROR!`, но
[`mod_event_socket`](../../src/mod/event_handlers/mod_event_socket/mod_event_socket.c#L1555)
для **любого** неуспешного статуса API заменяет stream на
`-ERR amqp Command not found!`. Пустой успешный stream превращается в
`-ERR no reply`. Эта цепочка подтверждена исходниками и фактическим runtime
этапа 3. Установленный Core — ревизия `82bf16a286`; его SHA-256 до и после
проверок `85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145`.

Теперь API всегда пишет одну строку и возвращает `SWITCH_STATUS_SUCCESS`
после завершения вызова обработчика:

| Результат `mod_amqp_do_config(SWITCH_TRUE)` | Точное тело ESL `api/response` | Статус обработчика для Core |
| --- | --- | --- |
| Успех | `+OK mod_amqp configuration reloaded\n` | `SWITCH_STATUS_SUCCESS` |
| Ошибка | `-ERR mod_amqp configuration reload failed\n` | `SWITCH_STATUS_SUCCESS` |

`switch_status_t` теперь означает, что **API-обработчик выполнился и сформировал
ответ**, а результат операции передаётся в stream. Вызывающие `switch_api_execute()`
должны читать тело; проверка только return status больше не отличает ошибочный
reload от успешного. Это требуется поведением используемого `mod_event_socket`.
Семантика `mod_amqp_do_config()` и состояния после его ошибок не менялась.
Текст ошибки намеренно фиксированный: `mod_amqp_do_config()` возвращает только
общий status и не передаёт безопасную типизированную причину. Вывод текстов
низкоуровневых ошибок мог бы раскрыть параметры подключения; добавление
причин потребовало бы изменения reload/lifecycle вне этой задачи.

## Проверки через ESL

К 24 прежним integration-кейсам добавлены пять проверок. Изолированный тестовый
процесс загружает настоящий установленный `mod_event_socket.so`, а тестовый DSO
регистрирует production-функцию `amqp_reload()` в Core API registry. Клиент
соединяется с `127.0.0.1:28741`, проходит тестовую авторизацию и посылает
`api amqp`. Тело ответа читается из реального ESL `api/response`, с проверкой
точного текста. Таким образом исполняются настоящие
`switch_api_execute()` и `mod_event_socket`, без подмены их обработки.

| Условие | Ожидаемый ответ | Результат |
| --- | --- | --- |
| Успешный reload | `+OK … reloaded` | PASS, новый профиль активирован |
| Некорректный поздний `mode` | `-ERR … failed` | PASS, прежний профиль сохранён |
| Занят `lifecycle_mutex` | `-ERR … failed` | PASS, переключения нет |
| Ошибка producer teardown | `-ERR … failed` | PASS, retained owner сохранён |
| Ошибка активации позднего producer | `-ERR … failed` | PASS, созданный новый набор очищен |

Отказы создаются только тестовыми wrappers уже существующего integration-fixture.
Сетевые sender-потоки заменены тестовыми joinable workers; RabbitMQ этим
процессом не используется. Тестовый `mod_event_socket` слушает только loopback.
Используется установленный DSO той же среды; новый `mod_amqp.so` в него не
загружается. Действующий сервис работает в другом процессе.

## Изменённые файлы

| Файл | Содержание |
| --- | --- |
| [`mod_amqp.c`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L47) | Текст двух ответов и разделение статуса API от результата reload |
| [`producer_integration_helpers.h`](../../src/mod/event_handlers/mod_amqp/test/producer_integration_helpers.h#L121) | Прежние 24 теста читают stream вместо return status API |
| [`api_reply_cases.h`](../../src/mod/event_handlers/mod_amqp/test/api_reply_cases.h) | Пять ошибок/успех через ESL |
| [`api_reply_helpers.h`](../../src/mod/event_handlers/mod_amqp/test/api_reply_helpers.h), [`api_reply_proxy.c`](../../src/mod/event_handlers/mod_amqp/test/api_reply_proxy.c) | Loopback ESL client и test-only регистрация API |
| [`test_producer_lifecycle.c`](../../src/mod/event_handlers/mod_amqp/test/test_producer_lifecycle.c), [`test/conf/freeswitch.xml`](../../src/mod/event_handlers/mod_amqp/test/conf/freeswitch.xml) | Подключение изолированных модулей и конфигурация тестового порта |
| [`Makefile.am`](../../src/mod/event_handlers/mod_amqp/Makefile.am), [`run_filter_engine_sanitizers.sh`](../../src/mod/event_handlers/mod_amqp/test/run_filter_engine_sanitizers.sh), [`test/README.md`](../../src/mod/event_handlers/mod_amqp/test/README.md) | Сборка proxy DSO, sanitizer и инструкция по тестам |

Core, `mod_amqp_do_config()`, producer lifecycle, transport, JSON, routing и
правила переключения набора не изменены. Новые runtime hooks в production
module не добавлялись.

## Команды и результаты

Команды выполнялись в `freeswitch-dev` из `/usr/src/freeswitch`; ни одна из них
не вызывает `install`, `fs_cli reload`, `reloadxml` или сервисный shutdown.

```sh
automake --foreign src/mod/event_handlers/mod_amqp/Makefile
./config.status src/mod/event_handlers/mod_amqp/Makefile
```

Обе завершились с exit 0. Из каталога модуля:

```sh
make -j2 mod_amqp.la check \
  mod_amqp_la_LIBADD="-L/usr/local/freeswitch/lib -lfreeswitch" \
  mod_amqp_la_LDFLAGS="-avoid-version -module -no-undefined -shared -lrabbitmq -Wl,-z,defs -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_filter_engine_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so" \
  test_test_filter_engine_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_producer_lifecycle_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq" \
  test_test_producer_lifecycle_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib"
```

Exit 0: `make check` PASS=3, FAIL=0; engine **19/19**, lifecycle **18/18**,
integration **29/29** (24 прежних + 5 ESL). Makefile использует
`SWITCH_AM_CFLAGS`/`SWITCH_ANSI_CFLAGS` с `-Werror`; сборка завершилась без
ослабления этой проверки. Новый `.libs/mod_amqp.so` имеет DT_NEEDED
`libfreeswitch.so.1` и RUNPATH `/usr/local/freeswitch/lib`.

```sh
MOD_AMQP_SANITIZER_TEST=test_producer_integration \
  sh test/run_filter_engine_sanitizers.sh \
  /tmp/mod-amqp-api-reply-sanitizers/integration /usr/local/freeswitch/lib
MOD_AMQP_SANITIZER_TEST=test_filter_engine \
  sh test/run_filter_engine_sanitizers.sh \
  /tmp/mod-amqp-api-reply-sanitizers/engine /usr/local/freeswitch/lib
```

Оба runner — exit 0. Integration ASan/UBSan/LSan и TSan — **29/29** каждый;
standalone engine ASan/UBSan/LSan и TSan — **19/19** каждый. Для sanitizer
бинарников используются `-Werror`, `-O1 -g`, `-fno-omit-frame-pointer`,
`detect_leaks=1:halt_on_error=1` и 90-секундный timeout. Журналы находятся
в указанных `/tmp` каталогах; журнал `make check` —
`/tmp/mod-amqp-api-reply-make-check.log`. `git diff --check` — exit 0.

Sanitizers инструментируют исходники `mod_amqp`, proxy и тестовый клиент,
но установленный Core и `mod_event_socket.so` остаются неинструментированными.
Настоящие AMQP sender/command/logging I/O потоки не исполняются тестом.
Отсутствие сообщений sanitizers в этом прогоне не является доказательством
отсутствия всех гонок или ошибок памяти в работающем сервисе. Указанный
loopback-порт занят только на время integration-процесса; параллельный запуск
двух таких процессов потребует другого порта.

## Состояние перед установкой

Новый бинарник остался только в build tree:
`/usr/src/freeswitch/src/mod/event_handlers/mod_amqp/.libs/mod_amqp.so`
(SHA-256 `31b8dba5b522808a1bc95f07ccde8b332eaca9e4d2432899ec9d48bfbc583d1f`).
Установленный `/usr/local/freeswitch/mod/mod_amqp.so` сохранил прежний SHA-256
`2e3ce5943c029965ab32e43701b4f9243b51f65b598fcd28634d020184a812a8`.
Рабочий XML сохранил SHA-256
`d81022edc64b75ec784e18b5408876901dba0b81fcb761495af414077e7f851a`.
На момент изолированных тестов модуль в сервис **не устанавливался и не
перезагружался**. Результат последующего разрешённого runtime-прогона приведён
ниже.

## Последующий runtime-тест с установленным модулем

По отдельному запросу пользователя пересобранный `mod_amqp.so` установлен
в `freeswitch-dev` и проверен через реальный `fs_cli`/ESL 27 октября 2026 года.
Перед установкой `show channels count` вернул `0 total`, Core совпал с
зафиксированным SHA-256. Созданы приватные резервные копии исходного XML и
установленного `.so` в `freeswitch-dev:/tmp/mod-amqp-api-live.XDzscu/`.

`make -j2 mod_amqp.la` с указанными выше `LIBADD`/`LDFLAGS` завершился с
exit 0. В `/usr/local/freeswitch/mod/mod_amqp.so` атомарно установлен только
новый бинарник (SHA-256
`31b8dba5b522808a1bc95f07ccde8b332eaca9e4d2432899ec9d48bfbc583d1f`).
`timeout 45s fs_cli -x "reload mod_amqp"` завершился с exit 0 и вывел
`module unloaded` / `module loaded`. Core не переустанавливался.

| Реальный вызов | Фактический ответ | Проверка |
| --- | --- | --- |
| `fs_cli -x amqp` на исходном XML | `+OK mod_amqp configuration reloaded` | Точный ожидаемый успех |
| `fs_cli -x amqp` после `reloadxml` с временным неверным `mode` у `osyrbu` | `-ERR mod_amqp configuration reload failed` | Точная ожидаемая ошибка; модуль остался загружен |
| `fs_cli -x amqp` после восстановления XML и `reloadxml` | `+OK mod_amqp configuration reloaded` | Повторная успешная работа |

Для ошибочного случая добавлялся только `<filter mode="invalid-api-live-test"/>`
в последний producer-профиль. При выполнении проверки действовал shell trap,
который восстанавливал XML из резервной копии и повторял `reloadxml` + API reload
даже при ошибке команды. Журнал FreeSWITCH подтвердил отказ подготовки
`producer profile[osyrbu]`. Первая попытка вставки не нашла профиль из-за
ошибки тестового шаблона и завершилась **до изменения XML**; trap также
восстановил конфигурацию. После исправления тестового шаблона нужный ответ
получен. Это не ошибка production API.

`fs_cli` вернул код 0 и для текстового `-ERR`, поэтому тест сравнивал точную
строку ответа, а не только exit code. Финальные `cmp` исходного и рабочего XML,
проверка его SHA-256
`d81022edc64b75ec784e18b5408876901dba0b81fcb761495af414077e7f851a`
и сверка Core SHA-256 прошли (exit 0). `module_exists mod_amqp` вернул `true`,
`show channels count` — `0 total`; контейнеры `freeswitch-dev` и `rabbitmq`
остались запущены. RabbitMQ не перезапускался. Тестовый звонок и повторный тест
отказа брокера в этом прогоне не выполнялись: проверялся новый API-ответ.
