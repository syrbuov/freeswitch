# mod_amqp Filter Engine v1 — этап 3: интеграция producer

> Этот документ фиксирует приёмку исходников до установки в сервис.
> Последующая разрешённая установка, реальный звонок и проверка отключения
> RabbitMQ описаны в [runtime-отчёте](filter-engine-stage3-runtime.md).
> В нём отдельно зафиксирована потеря одного события при отказе брокера.

Дата завершения отчёта: 27 октября 2026 года. Реализация и основные прогоны:
26 октября; финальная проверка после возобновления работы — 27 октября.
Ветка: `codex/mod-amqp-filter-engine-stage3`. Изменения оставлены в рабочем
дереве для review на момент приёмки исходников, до установки в действующий сервис.

## 1. Результат и исходное состояние

Standalone Parser/Compiler/Matcher подключён к producer. Введены отдельная
подготовка всего producer-набора, активация, владение engine и проверка правил
до выделения сообщения/JSON. Legacy subscriptions сохраняют прежнюю кратность.
Ошибки подготовки сохраняют старый набор; после начала teardown rollback нет.

Пройдены штатная сборка с `-Werror`, 19 engine-тестов, 18 прежних lifecycle-тестов
и 24 новых интеграционных теста. Результаты sanitizers приведены ниже отдельно
от функциональных проверок. Runtime smoke и RabbitMQ end-to-end **не выполнялись**:
отдельная среда для этих проверок не была явно разрешена. Установка, CLI reload,
unload/load работающего модуля и изменение рабочей конфигурации не выполнялись.

Исходный HEAD: `7d20cfbdb75bf62756a8d835c106f0c569bd048f` — коммит этапа 2.
Baseline этапа 1 `f6c581830a6e7c212b63b9e4ee9261ee7b187f8f` подтверждён как предок.
Diff между ними: 10 файлов, 1707 добавлений / 3 удаления, standalone engine,
тесты, Makefile и документация. До начала этапа 3 tracked-изменений не было.

Прочитаны [архитектурная проверка](filter-engine-review.md),
[отчёт этапа 1](producer-lifecycle-stage1.md), [отчёт этапа 2](filter-engine-stage2.md)
и [HANDOFF](HANDOFF.md). Применимые `AGENTS.md` в проверенных родительских
каталогах и каталогах модуля/документации не найдены.

До начала работы уже существовали untracked `.vscode/tasks.json`, CMake/Ninja
артефакты `build/`, дополнительные каталоги модулей `mod_example`, `mod_unimrcp`,
`mod_vosk`, `mod_wsbridge`, `mod_event_grpc`, тестовые binaries, а также
`test/adoption-token.dat`. Они не включены в изменения этапа; содержимое token
не читалось. Reset/clean и checkout с потерей локальных файлов не использовались.

## 2. Окончательный XML-контракт

Проверяется не более одного **непосредственного** `<filter>` внутри producer
`<profile>`. Обработка находится в
[`mod_amqp_producer_prepare()`, mod_amqp_producer.c:215](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L215).

| Конфигурация | Результат |
| --- | --- |
| Нет `filter` | Legacy |
| `<filter mode="legacy"/>` | Legacy |
| `<filter mode="rules">…</filter>` | Rules, передача существующему Parser этапа 2 |
| `filter` без явного `mode`, неизвестный mode, несколько `filter` | Ошибка подготовки всего producer-набора |
| Дочернее содержимое в legacy filter | Не исполняется, выдаётся предупреждение |
| `event_filter` в rules | Игнорируется, выдаётся предупреждение |
| `<filter mode="rules"/>` | Deny all, ноль bindings |
| `<rule/>` | Ошибка подготовки |

Mode регистрозависим; DTD default не может подставить отсутствующий mode.
Грамматика Parser/Compiler/Matcher этапа 2 не изменена. В legacy дополнительные
атрибуты filter не используются; в rules строгую проверку выполняет Parser.
Вложенный, не непосредственный filter не выбирает режим producer.

```xml
<profile name="tenant-acme">
  <params>
    <param name="exchange-name" value="TAP.Events"/>
    <param name="format_fields" value="Event-Name"/>
  </params>
  <filter mode="rules">
    <rule>
      <event name="CUSTOM"/>
      <condition field="Event-Subclass" op="eq" value="sofia::register"/>
      <condition field="variable_tenant" op="eq" value="acme"/>
    </rule>
  </filter>
  <!-- connections задаются существующим форматом mod_amqp -->
</profile>
```

Selector принимает точные `CUSTOM` и `SWITCH_EVENT_CUSTOM`, аналогично остальные
имена, включая `ALL`/`SWITCH_EVENT_ALL`. Иных префиксов и изменения регистра нет.
Между правилами OR, между selectors одного правила OR, между conditions AND.
Правило без selectors проверяет любое событие; разрешение всех событий можно
выразить явным selector ALL. Поддерживается только `eq`.

Event-Name задаётся selector и проверяется по `event_id`; condition Event-Name
отклоняется. Event-Subclass читает `event->subclass_name`. Имена полей сравниваются
без учёта ASCII-регистра, значения — побайтово с учётом регистра. Для обычного
header действует ANY по всем одноимённым nodes и элементам массивов. Отсутствие
значения отличается от пустого значения. `_body` запрещён. Лимиты сохранены:
1024 правила, 32 conditions на правило, 4096 байт значения, 255 байт имени поля,
4 MiB копий field/value strings на DTO и отдельно на engine.

Legacy использует прежние defaults, `switch_separate_string()`,
`switch_name_event()`, `^subclass` и обработку нераспознанных event names.
Например, `ALL,DTMF,DTMF` по-прежнему даёт три обработки DTMF. Новая гарантия
одного прохода относится к rules, а не к legacy и не к exactly-once RabbitMQ.

Отдельное изменение проверки конфигурации: некорректная producer connection
без имени теперь отклоняет подготовку всего набора, вместо прежнего пропуска
этой connection. Это позволяет сохранять старый набор при ошибке подготовки.
Остальные defaults и преобразования connection parameters сохранены.

## 3. Владение и порядок активации

В [`mod_amqp.h:96`](../../src/mod/event_handlers/mod_amqp/mod_amqp.h#L96) добавлены
`mod_amqp_filter_mode_t`, management-only `mod_amqp_producer_state_t` и opaque
`mod_amqp_producer_prepared_t`. Профиль хранит `filter_mode`, `filter_engine`,
`activation_state` и прежние индивидуальные `event_nodes[]`.

| Объект / функция | Владение и действия |
| --- | --- |
| `mod_amqp_producer_prepare()` | Создаёт wrapper, отдельный pool и неопубликованный profile-кандидат; копирует строки параметров, legacy subscriptions и connection settings; parse/compile rules; DTO сразу уничтожается |
| `mod_amqp_connection_parse()` | Выделенный из прежнего create разбор настроек; не вызывает AMQP API и не создаёт sockets/connection handles |
| Prepared connection records | Записи конфигурации в pool, `state == NULL`; `profile->conn_root` до активации пуст. Это только собственные allocations, не соединения |
| `mod_amqp_producer_prepared_destroy()` | Освобождает ещё не переданный engine/pool и wrapper; никогда не удаляет запись active hash |
| `mod_amqp_producer_activate()` | Забирает candidate у wrapper (`prepared->profile = NULL`) ровно один раз, включая engine/pool. Повторная активация wrapper отклоняется |
| `mod_amqp_producer_create()` | Совместимая внутренняя обёртка prepare → activate → prepared_destroy для создания одного профиля |

Подготовка не создаёт mutex состояния, очередь, worker, Core bindings или
живые AMQP connections, не меняет active hash. Она допускает имя уже активного
профиля. Имена нового набора проверяются на непустоту и дубликаты до teardown.
Все операции управления требуют `lifecycle_mutex`; output slot prepare должен
быть пустым. Вызовы из callback не поддерживаются.

Активация выполняет:

1. Проверку отсутствия живого владельца имени в hash.
2. Создание `state_mutex`, начального running, runtime connection records из
   ранее скопированных settings и очереди.
3. Публикацию владельца в active hash для доступности при failed cleanup.
4. Создание joinable sender; thread handle сохраняется только при успехе API.
5. Регистрацию каждого subscription и сохранение индивидуального handle.
6. Переход management-состояния ACTIVATING → ACTIVE.

К моменту первого bind immutable configuration/engine, очередь и успешно
созданный sender готовы. Callback может исполниться до возврата bind и до
установки ACTIVE: он не читает management-состояние, готовность определяется
опубликованными данными и синхронизированным running.

В rules регистрируется только `mod_amqp_filter_subscriptions()`:
пустой план → ноль bindings; общий план → один ALL; иначе уникальные конкретные
IDs с NULL subclass. Массив из `SWITCH_EVENT_ALL` slots достаточен: конкретных
IDs ровно столько (0 … ALL−1), а ALL никогда не сосуществует с ними в плане.
Перед активацией вместимость проверяется. Число правил размером storage не
ограничивается: тест проверяет 1024 правила с единственной подпиской.

Реализация: [подготовка плана:411](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L411),
[освобождение prepared:445](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L445),
[активация:459](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L459),
[разбор connection settings:195](../../src/mod/event_handlers/mod_amqp/mod_amqp_connection.c#L195).

## 4. Callback, breaker и destroy

[`mod_amqp_producer_event_handler():87`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L87)
проверяет profile/running и circuit breaker, затем в rules вызывает Matcher.
False возвращает управление до `switch_malloc`, JSON и enqueue. True продолжает
старый путь единожды; Matcher не перечисляет совпавшие правила вызывающему коду.
Lifecycle mutex в callback/sender не берётся; borrowed event pointers не сохраняются.

Все production-чтения и записи `circuit_breaker_reset_time` находятся в callback
на строках 107 и 127 и защищены `state_mutex`. Начальный ноль создаётся pool до
публикации. Сохранена политика: переполнение очереди устанавливает deadline
`now + circuit_breaker_ms * 1000`; приведение к `switch_time_t` выполняется до
умножения. Mutex не удерживается во время matcher, JSON, enqueue, AMQP I/O,
unbind или join. Одновременные callbacks могут уже пройти проверку до первого
переполнения: это прежняя политика, не строгий лимит одного сообщения/лога.

[`mod_amqp_producer_destroy():137`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L137):
индивидуальные unbind → stop под state_mutex → успешный join → удаление только
собственной hash entry → закрытие connections/очистка очереди → engine destroy
→ pool destroy. При ошибке любого unbind/join engine, pool и retained resources
сохраняются вместе с доступным через hash профилем. Уже снятые nodes и успешно
joined handle обнулены; повторный teardown их пропускает.

Барьер callback основан на настоящем Core RWLOCK:
[`switch_event_deliver():400`](../../src/switch_event.c#L400),
[`switch_event_unbind():2175`](../../src/switch_event.c#L2175).
Глобальный producer-unbind, refcount и конкурентный destroy engine не добавлялись.

Сравнение тел функций с HEAD подтвердило отсутствие изменений
`mod_amqp_producer_routing_key()`, `mod_amqp_producer_send()` и
`mod_amqp_producer_thread()`. JSON-вызов, формат сообщения и publish/reconnect
сохранены. Connection transport open/close не изменён.

## 5. Переключение и состояния после отказов

[`mod_amqp_do_config():175`](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L175)
сохраняет trylock, shutting_down и отказ reload из command worker. Используется
`switch_xml_open_cfg("amqp.conf", …)` — существующий XML snapshot; API `amqp`
не вызывает reloadxml.

Порядок: prepare всего набора → destroy всего старого producer-набора → activate
нового набора → пересоздание command/logging → восстановление logging callback.
До успешной подготовки соседние profiles не изменяются; в реализации они
остаются прежними и при ошибке producer teardown/activation.

| Отказ | Состояние и результат |
| --- | --- |
| Занят lifecycle mutex, shutdown или caller — command worker | Ошибка до переключения |
| XML/имя/дубликат/mode/rules/connection preparation | Уничтожены только новые prepared objects; весь старый producer-набор действует |
| Старый unbind/join | Переключение остановлено; новые bindings не создаются. Уже удалённая часть старого набора не восстанавливается; failed owner retained |
| Queue/hash/thread/bind activation | Дальнейшая активация прекращена; очистка всех уже активированных новых profiles и всех оставшихся prepared objects |
| Failed cleanup нового набора | Возврат ошибки; retained profiles/engines доступны через active hash для следующего teardown |
| Command/logging create/destroy или logger bind/unbind | Итоговая ошибка; producer-набор уже переключён, транзакционность всего модуля не обещается |
| Shutdown с failed teardown | `SWITCH_STATUS_NOUNLOAD`, ресурсы и DSO должны остаться доступны |
| Initial load с ошибкой config | Попытка полного shutdown; при успешной очистке GENERR. Если очистка не удалась — NOUNLOAD, критическая диагностика и закрепление DSO |

При unwind нового набора hash iterator продвигается **до** удаления текущей
записи, чтобы не читать освобождённый entry и не зациклиться на retained owner:
[`amqp_destroy_producers():155`](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L155).

Ошибка проходит через `mod_amqp_do_config()` в
[`amqp_reload():47`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L47).
Core [`switch_api_execute():2933`](../../src/switch_loadable_module.c#L2933)
возвращает этот status и пишет `COMMAND RETURNED ERROR!` при неуспехе.
Интеграционные тесты вызывают настоящую API-функцию; ESL/RabbitMQ для этого не нужны.

`logging_bound` исключает повторную регистрацию logger и учитывается shutdown.
Logger снимается до изменения logging hash (Core BINDLOCK даёт барьер callback),
после пересоздания регистрируется снова, в том числе при recoverable ошибке.
Две последовательные reload проверены настоящей доставкой Core log в production
`mod_amqp_logging_recv()` и появлением сообщения в logging queue.

Для корректного статуса соседних profiles минимально изменены их create/destroy:
публикация владельца до worker, joinable attributes, успешные output handles,
отказ удаления чужой hash entry и сохранение owner при failed join. В command
destroy также исправлено продвижение по connection list. Транспорт соседних
profiles не переписывался.

После начала teardown нет rollback, бесшовности или переноса очередей.
Существует окно без subscriptions, остатки очередей удаляемых profiles теряются;
при ошибке поздней активации часть новых profiles могла уже обработать события.
NOUNLOAD при первоначальной загрузке закрепляет модуль как permanent в Core;
shutting_down остаётся установленным после failed shutdown. Восстановление
работоспособности такого состояния через обычный API не гарантируется, может
потребоваться перезапуск процесса. Этот путь не проверен через live module loader.

## 6. Проверенная среда и команды

Контейнер `freeswitch-dev`, образ `freeswitch-local-dev:mod_speechkit_vscode`,
volume проекта `/usr/src/freeswitch`. rabbitmq-c `0.11.0`.
Установленный Core — `82bf16a286`; кешированный Core в `.libs` — другая сборка
(`ae5ffee`). Кеш не устанавливался и для окончательной линковки не использован.

Перед прогонами сверены headers `switch.h`, `switch_event.h`, `switch_types.h`,
`switch_xml.h`, `switch_apr.h`; финально также `switch_core.h`, `switch_log.h`,
`switch_module_interfaces.h`, `switch_loadable_module.h`: побайтово совпадают
с `/usr/local/freeswitch/include/freeswitch/`. Diff event/XML/log/hash/hashtable/
loadable-module Core sources против `82bf16a286` пуст. Generated version header
по-прежнему отражает revision исходного дерева; это не версия загруженного DSO.

Установленный Core до и после работ имеет SHA-256:

```text
85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145
```

`/proc/1/maps` показывает прежние установленные Core и mod_amqp работающего
процесса. Все три тестовых executable через `ldd` используют
`/usr/local/freeswitch/lib/libfreeswitch.so.1`.

Команды выполнялись через `docker exec freeswitch-dev sh -c '…'`.
Подготовка generated Makefile, без изменения Core:

```sh
cd /usr/src/freeswitch
automake --foreign src/mod/event_handlers/mod_amqp/Makefile
./config.status src/mod/event_handlers/mod_amqp/Makefile
```

Фактическая итоговая штатная сборка и `make check`:

```sh
cd /usr/src/freeswitch/src/mod/event_handlers/mod_amqp
make -j2 mod_amqp.la check \
  mod_amqp_la_LIBADD=/usr/local/freeswitch/lib/libfreeswitch.so \
  mod_amqp_la_LDFLAGS="-avoid-version -module -no-undefined -shared -lrabbitmq -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_filter_engine_LDADD=/usr/local/freeswitch/lib/libfreeswitch.so \
  test_test_filter_engine_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_producer_lifecycle_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq" \
  test_test_producer_lifecycle_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib"
```

Integration LDADD/LDFLAGS наследуют lifecycle-переменные. Compiler flags из
штатного Makefile включают `-Werror`, `-Wall`, C99 и проверку declarations.
Generated Makefile/object files не входят в исходный diff.

Финальная проверка выявила особенность libtool: переданный прямой путь к Core
`.so` в LIBADD модуля не оставил DT_NEEDED. Поэтому модуль отдельно перелинкован
через `-L/-l`, с дополнительной проверкой всех символов `-z defs`:

```sh
make -W mod_amqp_la-mod_amqp.lo V=1 mod_amqp.la \
  mod_amqp_la_LIBADD="-L/usr/local/freeswitch/lib -lfreeswitch" \
  mod_amqp_la_LDFLAGS="-avoid-version -module -no-undefined -shared -lrabbitmq -Wl,-z,defs -Wl,-rpath,/usr/local/freeswitch/lib"
ldd .libs/mod_amqp.so
readelf -d .libs/mod_amqp.so
```

Exit 0. Теперь DT_NEEDED содержит `libfreeswitch.so.1`, RUNPATH —
`/usr/local/freeswitch/lib`; `ldd` подтверждает установленную библиотеку.
Для повторения module build в этой смешанной среде следует использовать именно
последний вариант LIBADD/LDFLAGS. Это проверка сборки/зависимостей, не live load.
Корневой `make mod_amqp-install` не выполнялся.

Sanitizers:

```sh
MOD_AMQP_SANITIZER_TEST=test_producer_integration \
  sh test/run_filter_engine_sanitizers.sh \
  /tmp/mod-amqp-stage3/verified-sanitizers /usr/local/freeswitch/lib
```

ASan+UBSan: `detect_leaks=1:halt_on_error=1`, UBSan halt_on_error; TSan:
halt_on_error. Suppressions нет. Бинарники создаются отдельно, с `-O1 -g`,
`-fno-omit-frame-pointer`, `-Werror`; каждый запуск ограничен `timeout 90s`.
Integration всегда использует полный event engine, даже если установлена
test-only переменная выбора minimal для standalone engine.

## 7. Результаты и устройство тестов

| Проверка | Результат |
| --- | --- |
| Штатная сборка модуля с `-Werror` | PASS |
| Окончательная линковка модуля с установленным Core и `-z defs` | PASS, exit 0 |
| Standalone engine | 19/19, exit 0 |
| Прежний producer lifecycle suite | 18/18, exit 0 |
| Новые integration cases | 24/24, exit 0 |
| Automake `make check` | 3 executables, PASS=3, FAIL=0, exit 0 |
| Integration ASan/UBSan + LSan | 24/24, процесс завершился успешно |
| Integration TSan | 24/24, процесс завершился успешно |
| Итоговый sanitizer runner | PASS обоих процессов, exit 0 |
| Diff/сохранение транспорта | `git diff --check` PASS; routing/send/sender без изменений |
| Runtime smoke / RabbitMQ end-to-end | Не выполнялись, не входят в выполненную приёмку исходников |

Результаты обычных прогонов: `test/test_filter_engine.log`,
`test/test_producer_lifecycle.log`, `test/test_producer_integration.log`.
Контейнерные журналы: `/tmp/mod-amqp-stage3/final-check.log`, `final-link.log`,
`verified-sanitizers-status.log`, `verified-sanitizers/*.log` и `*.build.log`.
Предыдущий финальный прогон также сохранён в `final-sanitizers/`; после перерыва
повторены sanitizers, чтобы получить доступный код завершения всего runner.
Журналы `/tmp` не переживут пересоздание контейнера.

[`test_producer_integration.c`](../../src/mod/event_handlers/mod_amqp/test/test_producer_integration.c)
использует общий fixture из lifecycle-теста, но отдельный набор cases.
Production sources включены с узкими test-local wrappers, без hooks в модуле.
Настоящие Core events, XML, headers, bindings/unbind, очереди, mutex, pool,
thread creation/join, JSON и logging delivery используются непосредственно.

Producer sender заменён joinable worker с production accessor running;
command/logging workers завершаются без сетевого I/O. Их create/destroy и
logging callback остаются production-кодом. XML snapshot для API reload
подставляется wrapper вокруг `switch_xml_open_cfg`, без изменения конфигурации.
Доставка в тестовый producer callback учитывает только явно помеченные тестовые
события, исключая ambient Core events. Счётчики callback, allocation, JSON,
enqueue и engine destruction защищены тестовым mutex.

Инструментированы все девять mod_amqp production C sources и fixture,
включённые/скомпилированные в integration executable. Установленные
`libfreeswitch`, rabbitmq-c и остальные DSO **не инструментированы**.
Настоящие тела сетевых workers скомпилированы, но в этих тестах не исполняются.
Успешный TSan не является доказательством отсутствия гонок во всём Core/модуле.

Соответствие обязательным сценариям:

| Группа | Integration cases / проверка |
| --- | --- |
| Legacy defaults, explicit legacy, дубли, subclass | `legacy_default_explicit_and_subclasses`, плюс прежние 18 lifecycle cases |
| Ошибочные modes, несколько filter, поздняя ошибка | `invalid_modes_preserve_entire_old_set` — два старых profiles сохраняют handles и доставку |
| Игнорирование event_filter, несколько совпавших rules | `rules_ignore_legacy_and_match_once` — 1 callback / 1 allocation / 1 JSON / 1 enqueue |
| Deny all | `empty_rules_deny_all` — ноль bindings и сообщений |
| ALL без overlap, два независимых profiles | `general_specific_rules_and_independent_profiles` |
| Отказ matcher до allocation/JSON/enqueue | `rejection_before_allocation_json_and_enqueue` |
| Подготовка без runtime resources, жизнь после XML/DTO | `preparation_has_no_resources_and_outlives_xml` |
| Чужой hash owner, повторная активация, дубликаты имён | `prepared_same_name_never_deletes_active_owner`, `duplicate_and_missing_names_fail_before_switch` |
| Ошибки queue/thread/hash/bind позднего профиля | `activation_failures_clean_entire_new_set` — очищается и ранее активированный профиль |
| Ошибка каждого bind внутри rules profile | `partial_rules_bindings_fail_at_each_position` |
| Failed unbind/join, retained engine, retry | `retained_engine_after_unbind_and_join_failure`, `activation_failure_with_failed_cleanup_remains_reachable` |
| Callback/sender barriers | `held_callback_blocks_engine_destruction_and_reload_shutdown`, `sender_barrier_retains_engine` |
| Снятие всех старых bindings до первого нового | `all_old_bindings_removed_before_any_new_binding` |
| Teardown failure и отказ нового activation | `teardown_failure_never_activates_new_set` |
| Concurrent/reentrant/command-worker/shutdown policy | `management_reentrancy_command_worker_and_shutdown` и удерживаемый callback |
| Logging после reload | `logging_rebound_after_successful_reload` — два reload, реальные Core logs и сообщения в queue |
| Ошибки соседних profiles доходят до API | `adjacent_profile_errors_reach_api`, `adjacent_creation_and_join_failures_reach_api` |
| Breaker под нагрузкой | `parallel_callbacks_queue_overflow_and_breaker`: 8 threads × 500 доставок, queue capacity=1 |
| Максимальная вместимость subscriptions и 1024 rules | `maximum_unique_subscriptions_and_more_rules_than_bindings` |
| Ошибка connection preparation | `invalid_connection_preparation_preserves_old_set` |

### Исправленные проблемы тестовой среды и неуспешные прогоны

Начальный fixture с пустым `<modules/>` оказался недостаточной изоляцией:
Core при нулевом количестве загруженных модулей сканирует `mod_dir` и пытается
загрузить все установленные DSOs. Это обнаружено по подробному журналу нового
logging-теста. В обоих test drivers каталог модулей теперь явно указывает на
`test/conf`, где нет DSO; встроенные Core modules при полном init остаются.
Рабочая конфигурация и действующий процесс при этом не менялись. Утверждение
старых отчётов о достаточности одного пустого modules list для изоляции следует
считать уточнённым этим результатом.

Первый sanitizer-прогон integration неверно использовал SCF_MINIMAL вместе с
modload: ASan завершился с exit 1 при загрузке mod_conference, TSan — exit 66.
Следующая попытка настоящего minimal Core не доставляла события и закончилась
11/20 cases, exit 9. Эти прогоны **не считаются успешными**. Integration переведён
на полный event engine с проверкой `switch_event_running()`. Дополнительно
исправлен тестовый logging level (`err`, а не `error`). Последующие полные
изолированные integration-прогоны прошли без suppressions.

## 8. Изменённые файлы и оставшиеся ограничения

| Файлы | Изменения |
| --- | --- |
| `mod_amqp.h`, `mod_amqp_producer.c` | Режим/состояние/engine, prepare/activate/release, matcher в callback, breaker mutex, engine lifetime |
| `mod_amqp_utils.c`, `mod_amqp.c` | Подготовка producer-набора, последовательное переключение, unwind, статусы и logger ownership; load/shutdown cleanup |
| `mod_amqp_connection.c` | Выделение чистого parser settings из create; transport не менялся |
| `mod_amqp_command.c`, `mod_amqp_logging.c` | Проверяемые join/creation и доступность владельцев при failed cleanup общего reload |
| `Makefile.am` | Integration executable и engine sources для lifecycle test |
| `test/test_producer_lifecycle.c` | Общий fixture и wrappers для отдельного integration executable; прежние 18 cases сохранены |
| `test/test_filter_engine.c` | Изоляция mod_dir тестового процесса; прежние 19 cases сохранены |
| `test/test_producer_integration.c`, `test/producer_integration_helpers.h`, `test/producer_integration_cases.h` | Новый integration suite |
| `test/run_filter_engine_sanitizers.sh`, `test/README.md` | Запуск и описание integration sanitizers, актуальная линковка/изоляция |
| `docs/mod_amqp/filter-engine-stage3.md` | Настоящий отчёт |

Все пути исходников в этой таблице относительны `src/mod/event_handlers/mod_amqp`.
Core, рабочие XML и standalone production engine sources не изменены.

Оставшиеся риски и непроверенное:

- Live module load/reload/shutdown, RabbitMQ publish/ack/reconnect, сетевые timeout
  и реальные sender loops не проверялись. Нет подтверждения end-to-end доставки.
- Старый Core в volume остаётся; обычная сборка без явного выбора установленной
  библиотеки снова может связаться с ним. Перед установкой требуется согласованная
  build-среда, отдельное разрешение и runtime-приёмка.
- Политика running у сетевых command/logging workers остаётся прежней:
  обычные несинхронизированные чтения/записи не исправлялись этим этапом.
  Замена workers в тестах исключает эти пути из TSan-покрытия; гарантия producer
  `state_mutex` не распространяется на них.
- Ошибки низкоуровневых Core allocations, которые завершают процесс через assert,
  не превращены в recoverable ошибки. Все возможные отказы ОС/APR не моделировались;
  проверены перечисленные точки инъекции, а engine allocation failures покрывает
  прежний standalone suite.
- Ожидание Core unbind зависит также от чужих callbacks; join может ждать сетевой
  вызов sender. Верхней границы времени reload/shutdown не добавлено.
- Вызов reload сторонним event callback не поддерживается: он может конфликтовать
  с Core read/write event lock. Producer callback сам управление не вызывает.
- Legacy permissive parsing и overlap сохранены намеренно. Regex, deny/negation,
  body matching, secondary index, перенос очередей и exactly-once не добавлены.

Приёмка исходников и указанных интеграционных гарантий выполнена. Runtime-приёмка
остаётся отдельным невыполненным этапом и не подменяется этими тестами.
