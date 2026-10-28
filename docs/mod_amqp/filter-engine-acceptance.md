> Актуализация 28 октября 2026 года: producer/logging lifecycle без изменения Core и с отключёнными command-профилями описан в [новом отчёте](filter-engine-lifecycle-without-core.md). Ниже сохранены результаты предыдущего этапа.

# Дополнение: проверка штатного load/unload, 27 октября 2026 года

**Вердикт: BLOCKED; штатный load/unload в production-код не внесён.**
[Технический отчёт](filter-engine-standard-lifecycle.md) отделяет успешный
контрольный путь от достижимого отказа Core loader. Три обычных
load→unload цикла на изолированной копии с одним изменением успешного load
NOUNLOAD→SUCCESS прошли. Отдельный forced unload во время config reload
вернул успех Core, но удалил registry/API при оставшемся DSO. Задержка
unbind в probe не меняла его результат. Кроме того, command worker может
выполнить unload mod_amqp через штатный console API на собственном потоке:
самоприсоединение невозможно, а возврат SUCCESS до выхода потока освободит
DSO слишком рано. Это не сценарии искусственного отказа unbind.

Прежняя permanent-доработка сохранена [отдельным patch](standard-lifecycle-artifacts/permanent-baseline.patch)
и остаётся в рабочем production diff; новый бинарник не установлен.
Синхронизация command/logging, зависимости сборки, worker-loop tests,
API-ответ и health не удалялись. Полная приёмка остаётся BLOCKED также
из-за незакрытого integration ASan и процессного shutdown, изложенных в
[hardening-отчёте](filter-engine-hardening.md). Следующие network/shutdown
тесты не объявлены пройденными после Core blocker.

---

# Обновление приёмки: 27 октября 2026 года

**Вердикт остаётся BLOCKED.** Исторический аудит ниже зафиксировал F1/F2 до hardening. Текущий reviewable diff, результаты и ограничения описаны в [hardening-отчёте](filter-engine-hardening.md). Пользователь выбрал permanent-политику без изменения Core; новый бинарник не установлен.

| Ранее выявленный пункт | Текущее состояние |
| --- | --- |
| F1, потеря Core registry/API при отказе module shutdown | Для динамических unload, forced unload и Core reload предотвращена: успешная загрузка возвращает NOUNLOAD, Core помечает модуль permanent до публикации; три изолированных loader-процесса прошли. Динамическое обновление бинарника запрещено. **Процессное завершение всё ещё блокирует приёмку:** Core пропускает permanent-модули, безопасного синхронного hook без изменения Core не найдено. |
| F2, data race command/logging running | Исправлена mutex-синхронизацией; 37 integration cases и TSan прошли, включая контролируемые worker-loop сценарии. Реальные сетевые таймауты и полное закрытие процесса не доказаны. |
| Health/initial load | status доступен через api amqp status. ACTIVE, DEGRADED, RESTART_REQUIRED различаются. При retained initial failure Core может сообщить успешную загрузку; проверять нужно status. |
| Sanitizer | Engine ASan/UBSan/LSan и TSan зелёные; integration TSan зелёный, integration ASan/UBSan/LSan падает в interceptor sigaltstack при APR thread exit. Минимальный Core/APR контрольный процесс ошибку не воспроизвёл; причина открыта. |

Ниже сохранён исходный аудит как baseline до этих изменений; его матрица и формулировки F1/F2 относятся к проверенному тогда HEAD, а не к нынешнему рабочему diff. Для текущих исходников используйте [hardening-отчёт](filter-engine-hardening.md), [loader logs](hardening-artifacts/loader-normal-v3.log) и [sanitizer summary](hardening-artifacts/sanitizer-policy-v2-run.log).

---

# mod_amqp Filter Engine v1: независимая окончательная проверка

Дата: 27 октября 2026 года. **Вердикт: BLOCKED.** Контракт фильтрации и штатное
переключение producer-набора подтверждены исходниками, повторными тестами и
прежней runtime-проверкой. Безопасный lifecycle *всего интегрированного модуля*
пока принять нельзя: аварийный `NOUNLOAD` в используемом Core оставляет модуль
в памяти, но теряет его запись в реестре, а command/logging workers читают флаг
остановки без синхронизации. Ни один из этих путей не закрыт имеющимися тестами.
Потеря события при отключении RabbitMQ относится к прежнему транспорту и в
этот вердикт не включена.

## Ревизия и граница проверки

- Ветка: `codex/mod-amqp-filter-engine-stage3`; проверенный HEAD:
  `7d8d9e948b6761a8ec8a8672009d9051cf27cb8a`.
- Baseline этапа 2: `7d20cfbdb75bf62756a8d835c106f0c569bd048f`.
  Этап 3: `7dc0a00e84a1be2db5d999b2b5b556eae819d174`. Исправление ответа API:
  HEAD `7d8d9e948b6761a8ec8a8672009d9051cf27cb8a`.
- На входе в аудит tracked-файлы были чистыми. В рабочем дереве уже были
  неотслеживаемые IDE/build-каталоги, сторонние модули, тестовые бинарники и
  приватный тестовый артефакт. Их содержимое не изменялось и в отчёт не
  включено. Мною созданы только этот отчёт и проверочные артефакты в
  [`acceptance-artifacts/`](acceptance-artifacts/). Для production-каталога
  `src/mod/event_handlers/mod_amqp` unstaged и staged patch пусты; SHA-256
  пустого patch: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Во время аудита появился посторонний tracked diff в `.vscode/settings.json`
  (добавлен `cmake.sourceDirectory`). Он сохранён без изменений отдельно как
  [`unrelated-vscode-settings.patch`](acceptance-artifacts/unrelated-vscode-settings.patch),
  SHA-256 `5dfdc7306e367aebbcb45273f74a6dda1f4f92e447b7ce09254aea8689102c21`.
  Этот diff не входит в проверяемый код `mod_amqp`; commit не создан.
- Применимых `AGENTS.md` в родительских каталогах, `docs/mod_amqp`, каталоге
  модуля и тестов не найдено. Предыдущие
  [архитектурный обзор](filter-engine-review.md),
  [этап 1](producer-lifecycle-stage1.md),
  [этап 2](filter-engine-stage2.md),
  [этап 3](filter-engine-stage3.md),
  [runtime](filter-engine-stage3-runtime.md) и
  [API-ответ](filter-engine-stage3-api-reply.md) использованы как проверяемые
  утверждения; код и тесты просмотрены независимо.

Проверялся исходный код репозитория и изолированные процессы в контейнере
`freeswitch-dev`. Установленный Core имеет SHA-256
`85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145`;
Core sources event/log/hash/loader между его ревизией `82bf16a286` и HEAD не
отличаются. Установленный `mod_amqp.so` до и после этой проверки имеет SHA-256
`31b8dba5b522808a1bc95f07ccde8b332eaca9e4d2432899ec9d48bfbc583d1f`.
Он был установлен по прежнему отдельному разрешению; **в этом аудите установка,
reload/unload, рабочий XML и RabbitMQ не затрагивались**.

## Матрица требований

`PASS` означает подтверждение указанным методом; это не утверждение об
отсутствии всех отказов ОС или сетевых ошибок.

| Гарантия | Статус | Основание и граница |
| --- | --- | --- |
| Нет `<filter>` → legacy; неизвестный mode отклоняется | PASS | [`mod_amqp_producer_prepare()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L245), integration/ESL cases |
| Legacy defaults, parsing `event_filter`, `^subclass` и кратность bindings | PASS | [producer:278–384](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L278), lifecycle/integration cases; перекрывающиеся legacy-подписки намеренно вызывают callback несколько раз |
| Rules: whitelist, OR правил/селекторов, AND условий | PASS | [parser](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_parser.c#L57), [matcher](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_matcher.c#L26), 19 engine cases |
| Ноль правил → ноль bindings и сообщений | PASS | [compiler:135–144](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_compiler.c#L135), [producer:411–421](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L411), integration |
| Канонические `event_id`/subclass, обычные и повторные headers/arrays | PASS | [parser:43–54](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_parser.c#L43), [matcher:3–24](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_matcher.c#L3), Core [`switch_event_get_header_idx()`](../../src/switch_event.c#L846); чтение event предполагает отсутствие одновременной мутации вызывающим кодом |
| План подписок без пересечения ALL и конкретных IDs | PASS | [compiler:135–144](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_compiler.c#L135), [Core delivery](../../src/switch_event.c#L400), integration cases |
| Одно выполнение на одну Core delivery rules-профилю | PASS | Один уникальный binding/ALL на профиль и boolean matcher: [activate](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L459), [matcher](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_matcher.c#L39); это не гарантия RabbitMQ exactly-once |
| Отказ matcher до allocation, JSON и enqueue | PASS | [callback:87–123](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L87), integration counters |
| Engine переживает XML/DTO и освобождается после unbind/join | PASS для producer | [compiler copies](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_compiler.c#L90), [prepared destroy](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L445), [producer destroy](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L137); ошибка unbind/join удерживает engine |
| Prepare всего набора до teardown без runtime-ресурсов и смены hash | PASS | [prepare set](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L128), [do_config](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L175), [connection parse](../../src/mod/event_handlers/mod_amqp/mod_amqp_connection.c#L195); отрицательные тесты |
| Дубликаты имён до teardown; readiness перед первым binding | PASS | [prepare set](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L128), [activate:459–530](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L459) |
| Все старые bindings сняты до новых; failed activation очищает новый набор | PASS | [do_config:189–200](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L189), integration fault injection |
| Retained profile доступен для повторной очистки внутри модуля | PASS с оговоркой | В hash он остаётся при unbind/join failure; после аварийного Core unload **повторный вызов через loader недоступен** (F1) |
| Безопасная аварийная выгрузка DSO/pool и повторный teardown через Core | **FAIL** | F1: Core удаляет registry entry и всё равно возвращает успешный unload при `NOUNLOAD`; воспроизведено отдельным loader-probe |
| Остановка producer/command/logging workers без гонок | **FAIL** | Producer синхронизирован; command/logging `running` имеет data race (F2) |
| API/ESL выдаёт точный `+OK`/`-ERR` | PASS | [API handler](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L47), [Core API](../../src/switch_loadable_module.c#L2933), [ESL](../../src/mod/event_handlers/mod_event_socket/mod_event_socket.c#L1555), 5 isolated ESL cases |
| Аварийный unbind в настоящем Core loader | **FAIL** | Отдельный процесс с отказом воспроизвёл F1; остальные OS/I/O failures не проверены |
| Реальный network-worker shutdown под TSan | NOT VERIFIED | Integration заменяет workers на idle; требуется отдельный I/O harness после F2 |

## Findings и последствия

### F1 — P0, блокирует приёмку: `NOUNLOAD` не сохраняет повторяемый unload

**Сценарий.** В штатном `reload mod_amqp` Core сначала удаляет модуль из
`module_hash`, затем вызывает `do_shutdown()`:
[`switch_loadable_module_unload_module():1898–1913`](../../src/switch_loadable_module.c#L1898).
Если [`mod_amqp_shutdown():120–151`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L120)
не смог снять binding или присоединить поток, он возвращает
`SWITCH_STATUS_NOUNLOAD`, сохраняя ресурсы. Core записывает этот статус в
`module->status`; DSO и module pool тогда не освобождаются, но
[`do_shutdown():2349–2382`](../../src/switch_loadable_module.c#L2349)
**безусловно возвращает `SWITCH_STATUS_SUCCESS`**. Внешний unload поэтому не
восстанавливает entry; повторный unload не найдёт модуль. При этом
[`mod_amqp_shutdown():116`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L116)
уже установил `shutting_down`, а [`mod_amqp_do_config():184`](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L184)
отвергает reload. Retained callbacks/workers могут оставаться живыми, но
штатного пути их очистки через loader уже нет. Поскольку hash entry удалена,
попытка новой загрузки тем же именем не будет отклонена на уровне registry;
[`mod_amqp_load():69`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L69)
сбросит process-global состояние, если код DSO ещё загружен. Безопасность
такого повторного load не доказана и полагаться на него нельзя.

**Самостоятельное воспроизведение.** Тестовый
[`loader-fault-main.c`](acceptance-artifacts/loader-fault-main.c) загрузил
настоящий build-tree `mod_amqp.so` в отдельный Core-процесс с приватным
[`freeswitch.xml`](acceptance-artifacts/loader-fault-freeswitch.xml) без
соединений. [`LD_PRELOAD` interposer](acceptance-artifacts/loader-fault-interposer.c)
отказал ровно одному `switch_event_unbind()`. Результат, exit 0:
`scenario=unload initial_load=0 failed_unbinds=1 unload_return=0
exists_after_unload=1`. Числовой `1` у `switch_loadable_module_exists()`
означает FALSE: Core сообщил об успешном unload, но registry entry исчезла
после неуспешного cleanup. Тест не запускает второй load поверх retained
ресурсов, чтобы не рисковать искусственным UAF даже в изолированном процессе.

При **ошибке первоначальной загрузки** модуль вызывает shutdown самостоятельно:
[`mod_amqp_load():82–89`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L82).
Если очистка снова не удалась, он возвращает `NOUNLOAD`; Core принимает этот
статус как успешную загрузку и помечает module `perm`:
[`switch_loadable_module_load_file():1720–1739`](../../src/switch_loadable_module.c#L1720).
DSO и pool сохраняются, но `shutting_down` уже установлен, штатный API reload
отклоняется, а обычный unload permanent-модуля запрещён. Это отдельная
недоказанная recovery-гарантия, не подтверждаемая нормальной загрузкой.
Второй отдельный процесс инъецировал отказ второго AMQP binding и постоянный
отказ unbind. Результат, exit 0:
`scenario=initial initial_load=0 failed_unbinds=3 unload_return=16
exists_after_unload=0`: Core принял initial `NOUNLOAD` как загрузку, а
последующий unload вернул код 16 (`SWITCH_STATUS_NOUNLOAD`); `exists=0`
означает, что permanent-модуль остался зарегистрирован. Оба процесса
завершились без вызова teardown намеренно удержанных ресурсов; ОС освободила
их при выходе. Действующий процесс FreeSWITCH не использовался.

**Происхождение.** Поведение Core предшествует этапу 3, а возврат `NOUNLOAD`
из модуля уже присутствовал в baseline этапа 2. Этап 3 расширил число
аварийных путей command/logging и заявил удержание ресурсов, но не решил
возврат управления через Core. Это не новая строка-регрессия в Core, однако
текущая интеграция не выполняет требование повторяемого безопасного teardown.
Обычный успешный unload/load и тест прямого вызова `mod_amqp_shutdown()` этот
сценарий не проверяют.

**Решение.** Не освобождать ресурсы живых callbacks/workers и не менять Core в
рамках текущего аудита. В отдельной задаче выбрать проверяемую политику:
исправить Core loader так, чтобы failed shutdown сохранял registry entry и
интерфейсы для повторной очистки, **либо** сделать модуль постоянно
невыгружаемым и выполнять только config reload с restart процесса после
неустранимого отказа. Второй вариант лишит операторов штатного `reload
mod_amqp`, поэтому требует явного продуктового решения. Для выбранного пути
проверить failed initial load, failed unload, повторную операцию и запрет
опасного повторного load в отдельном процессе. Пока F1 открыт, аварийный
shutdown требует управляемого restart процесса.

### F2 — P0, блокирует приёмку: data race флагов command/logging

[`mod_amqp_command_destroy():55`](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L55)
пишет `running=0`, а реальный worker читает его в
[`mod_amqp_command_thread():292,398,516`](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L292)
без mutex/atomic. Аналогично
[`mod_amqp_logging_destroy():127`](../../src/mod/event_handlers/mod_amqp/mod_amqp_logging.c#L127)
и [`mod_amqp_logging_thread():331`](../../src/mod/event_handlers/mod_amqp/mod_amqp_logging.c#L331).
Между записью и чтением нет happens-before до `join`; сам `join` ожидает выход
worker и не синхронизирует *сигнал* остановки. По модели памяти C это data race:
worker не обязан увидеть stop, значит teardown/reload может зависнуть и
оставить lifecycle mutex удержанным. Даже если конкретная сборка обычно
перечитывает поле из-за внешних вызовов, гарантия отсутствует.

**Происхождение.** Обычные unsynchronized чтения/записи существовали до этапа 3;
этап 3 изменил порядок публикации и проверку `join`, но флаги не исправил.
Это прежний дефект, влияющий на безопасность общего lifecycle. Тестовый
[`integration_other_thread()`](../../src/mod/event_handlers/mod_amqp/test/producer_integration_helpers.h#L68)
заменяет оба workers на `integration_idle`, поэтому успешный TSan не покрывает
эти чтения. Producer в отличие от них защищает `running` и breaker через
[`state_mutex`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L48).

**Решение.** В отдельной задаче синхронизировать stop/read в command и logging,
не удерживать mutex при AMQP I/O и `join`, ограничить ожидания сетевых операций;
добавить TSan-harness с настоящими worker loops и отказами/задержками I/O.

### F3 — P1, тестовая граница: network workers и прочие аварийные пути не покрыты

Текущие 18 lifecycle cases используют настоящий Core event engine и unbind,
но заменяют sender на joinable test worker:
[`test_producer_lifecycle.c:1–6,44–53`](../../src/mod/event_handlers/mod_amqp/test/test_producer_lifecycle.c#L1).
Integration включает production sources, настоящий Core JSON/queues/logger и
реальный `mod_event_socket`, но подменяет snapshot XML, доставку помеченных
events и сетевые workers:
[`test_producer_lifecycle.c:64–84`](../../src/mod/event_handlers/mod_amqp/test/test_producer_lifecycle.c#L64),
[`producer_integration_helpers.h:12–85`](../../src/mod/event_handlers/mod_amqp/test/producer_integration_helpers.h#L12).
Пять API cases проходят фактический ESL path через тестовый proxy DSO, который
делегирует production `amqp_reload()`:
[`api_reply_cases.h`](../../src/mod/event_handlers/mod_amqp/test/api_reply_cases.h#L1),
[`api_reply_proxy.c:16–26`](../../src/mod/event_handlers/mod_amqp/test/api_reply_proxy.c#L16).
Это адекватно для контрактов фильтрации и текста API, но не доказывает F2 и
реальные AMQP timeouts. Отдельный loader fixture выше теперь подтверждает два
конкретных пути F1, но не моделирует остальные OS/DSO/pool failures.
В прошлой [runtime-проверке](filter-engine-stage3-runtime.md) были штатный
unload/load, сохранение старого набора при неверном mode, звонок с двумя ногами
и реальные публикации; аварийные loader-пути там не вызывались.

**Решение.** Расширить приложенный временный loader fixture на отказ join,
проверку доступности API после `shutting_down`, повторный unload/load только
после безопасного исправления F1 и наблюдение pool/DSO references. Другой
fixture должен исполнять настоящие command/logging loops с mock AMQP I/O и
TSan. Эти инъекции нельзя запускать в действующем сервисе.

## Внесённые изменения и прежние ограничения

В diff этапа 3 и API-фикса не обнаружено новой подтверждённой регрессии
семантики rules/legacy на покрытых сценариях. Этап 3 **намеренно изменил**
обработку producer connection без имени: теперь
[`mod_amqp_connection_parse():204–211`](../../src/mod/event_handlers/mod_amqp/mod_amqp_connection.c#L204)
отклоняет подготовку всего набора, тогда как прежний create мог пропустить
эту connection. Это совместимость конфигурации, которую следует учитывать при
развёртывании. API-фикс изменил интерпретацию `switch_status_t`: обработчик
[`amqp_reload()`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L47)
возвращает `SUCCESS` и при отрицательном результате операции, чтобы ESL
сохранил `-ERR` из stream. Клиенты, прежде читавшие только status прямого
`switch_api_execute()`, должны читать тело ответа. Пять ESL cases это
проверяют; иных изменений transport или правил переключения API-фикс не внёс.

F1 относится к существовавшему до этапа 3 сочетанию возврата `NOUNLOAD` и
контракта Core loader; F2 — к существовавшим unsynchronized command/logging
workers. После этапа 3 оба пути по-прежнему влияют на безопасность общего
reload/shutdown и поэтому блокируют **текущую** приёмку, даже при отсутствии
новой строки-регрессии. Прежними, принятыми ограничениями остаются legacy
дубликаты, отсутствие rollback после начала teardown, окно без subscriptions,
потеря остатков очередей, отсутствие подтверждённой доставки RabbitMQ и
неограниченное ожидание чужих Core callbacks/сетевого I/O. Последняя пара
важна для эксплуатационной диагностики, но publisher confirms и transport
retry не включены в условия приёмки этого Filter Engine.

## Подтверждённый штатный путь и оставшиеся ограничения

Подготовка нового набора заканчивается до изменения старого:
[`amqp_prepare_set()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L128)
идёт до [`amqp_destroy_producers()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L155).
`mod_amqp_producer_prepare()` создаёт собственный pool, копии параметров и
соединений, компилирует engine; runtime connection/queue/thread/binding/hash
появляются только в `mod_amqp_producer_activate()`. Ошибка подготовки, включая
дубликат имени, оставляет старый набор. Перед первым новым binding сняты все
старые; ошибка поздней активации пытается убрать весь новый набор.

Unbind producer-биндинга является настоящим барьером текущих callbacks:
[`switch_event_deliver():405–419`](../../src/switch_event.c#L405) держит Core
RWLOCK на время вызова, а [`switch_event_unbind():2186–2201`](../../src/switch_event.c#L2186)
берёт write lock. `mod_amqp_producer_destroy()` сначала снимает свои nodes,
затем выставляет stop под `state_mutex`, присоединяет sender и только после
этого освобождает engine/pool. При failed unbind/join успешно освобождённые
handles обнуляются, profile удерживается в собственном hash; запись удаляется
только при совпадении указателя владельца. Обход hash при частичном unwind
продвигает iterator перед удалением current entry; реализация
[`switch_hashtable_next()`](../../src/switch_hashtable.c#L283) и
[`switch_hashtable_remove()`](../../src/switch_hashtable.c#L156) допускает это
без чтения удалённой entry. `lifecycle_mutex` не берут producer callback/sender;
управляющий `trylock` и проверка command worker избегают очевидного self-join.

Принятые ограничения штатного переключения: после начала teardown нет rollback,
есть окно без subscriptions и удаляются остатки старых очередей. При отказе
поздней активации уже активированная часть нового набора могла обработать
события. Legacy допускает повторные callback из пересекающихся bindings.
Command/logging не переключаются транзакционно с producer-набором. Успешный
unbind может ждать чужие callbacks Core; настоящий sender может задержать
`join` на сетевом I/O. Все обращения producer к
`circuit_breaker_reset_time` в callback защищены `state_mutex`; он не
удерживается через JSON/enqueue/I/O/unbind/join.

## Выполненные проверки и воспроизводимость

После фиксации HEAD обнаружено, что старые `make check` журналы записаны в
10:57, а `mod_amqp.c` менялся в 11:01. Поэтому результаты 19/18/29 из прежнего
[API-отчёта](filter-engine-stage3-api-reply.md) использованы лишь как фон.
Самостоятельно повторены тесты текущего HEAD. Обычный `make check` не пересобрал
integration executable: тот включает `mod_amqp.c` через другой исходник, не
отражённый в dependency graph. Второй прогон с `make -W
test/test_producer_integration.c` принудительно перекомпилировал этот executable.
Эта особенность сборки тестов требует сохранения при будущих проверках.

| Команда/проверка в `freeswitch-dev` | Exit code и результат |
| --- | --- |
| `make -j2 mod_amqp.la check` с overrides ниже | 0; 3 executables PASS |
| `make -j2 -W test/test_producer_integration.c test/test_producer_integration check` с теми же overrides | 0; 19/19 engine, 18/18 lifecycle, 29/29 integration (включая 5 ESL) |
| `make -j2 -W mod_amqp.c mod_amqp.la` с правильным Core | 0; production C перекомпилирован, module relinked с `-Werror` |
| `MOD_AMQP_SANITIZER_TEST=test_producer_integration sh test/run_filter_engine_sanitizers.sh /tmp/mod-amqp-acceptance-sanitizers/integration /usr/local/freeswitch/lib` | 0; ASan+UBSan+LSan 29/29, TSan 29/29 |
| `MOD_AMQP_SANITIZER_TEST=test_filter_engine sh test/run_filter_engine_sanitizers.sh /tmp/mod-amqp-acceptance-sanitizers/engine /usr/local/freeswitch/lib` | 0; ASan+UBSan+LSan 19/19, TSan 19/19 |
| `readelf -d`/`ldd` build-tree module/tests | 0; `libfreeswitch.so.1` из `/usr/local/freeswitch/lib`, `librabbitmq.so.4`, RUNPATH установленного Core |
| Два отдельных Core loader fault probes (`timeout 35s`, `LD_PRELOAD`) | 0/0; failed unload и failed initial load воспроизвели F1, подробности выше |
| `git diff --check` | 0 |

Точные overrides для module build: `mod_amqp_la_LIBADD="-L/usr/local/freeswitch/lib
-lfreeswitch"` и `mod_amqp_la_LDFLAGS="-avoid-version -module
-no-undefined -shared -lrabbitmq -Wl,-z,defs
-Wl,-rpath,/usr/local/freeswitch/lib"`; для engine/lifecycle tests — явные
`*_LDADD` к `/usr/local/freeswitch/lib/libfreeswitch.so`, для lifecycle также
`-lrabbitmq`, и `*_LDFLAGS` с `-no-undefined`/RUNPATH. Integration наследует
lifecycle flags. Их необходимость вызвана оставшимся в build tree другим Core
(`.libs/libfreeswitch.so.1.0.0`, SHA-256
`1e7f38c63165b17eea20e686de57f226c38c825e5541bb5c18f9e6a83275c035`);
обычный `libfreeswitch.la` не является доказательством линковки с установленным
Core. Generated Makefile содержит `SWITCH_AM_CFLAGS` с `-Werror`, `-Wall`, C99.
Headers и изученные Core sources соответствуют установленной ревизии. После
relink SHA-256 build-tree и установленного module одинаковый, но новый бинарник
**не устанавливался** в рамках аудита.

Sanitizer runner инструментирует production C, включённые в fixture, parser,
compiler, matcher, test proxy и клиент; установленный `libfreeswitch`,
`mod_event_socket` и rabbitmq-c не инструментированы. Integration запускает
полный event engine, standalone engine — minimal Core. Успешный TSan означает
отсутствие репортов только в исполненных путях; F2 worker loops тест заменяет.
Первый локальный вне контейнера запуск test executable завершился exit 127
(`libtpl.so.0` недоступна); его результат не засчитан. Достоверные повторы
выполнены в `freeswitch-dev`, где зависимости доступны.

Полные журналы этих повторов, `.trs`, sanitizer outputs, stdout сборки,
исходники временного loader harness, его два результата и контрольные SHA-256
сохранены в
[`docs/mod_amqp/acceptance-artifacts/`](acceptance-artifacts/), то есть в volume
репозитория вне контейнерного `/tmp`. Перед копированием проверены на строки
`password`, `token`, `authorization`, `credential`, `secret`, URI с credentials;
совпадений не найдено. Приватный test token и рабочий XML не копировались.

## Что требуется для снятия блокировки

1. Согласовать модульное поведение failed unload/initial load с фактическим
   loader-контрактом Core: живые callback/worker не должны потерять достижимого
   владельца, повторная загрузка поверх retained globals должна быть исключена.
   Проверить это fault injection в отдельном процессе; не менять Core без
   отдельного решения.
2. Убрать data races stop-флагов command/logging и проверить настоящий worker
   shutdown/timeout под TSan и контролируемым mock AMQP I/O.
3. После исправлений повторить `-Werror` build, 19/18/29 cases, sanitizers,
   failed initial load, failed unload/retry и штатный reload. Для будущего
   `make check` явно форсировать integration rebuild при изменении включаемых
   production `.c` либо исправить тестовые dependencies.

До закрытия F1 и F2 принять Filter Engine как безопасный lifecycle-модуль
нельзя. Поведение фильтрации v1 в штатном сценарии подтверждено; действующий
сервис во время этой проверки не изменялся.
