> Актуализация 28 октября 2026 года: producer/logging lifecycle без изменения Core и с отключёнными command-профилями описан в [новом отчёте](filter-engine-lifecycle-without-core.md). Ниже сохранены результаты предыдущего этапа.

# mod_amqp Filter Engine v1 — проверка штатного lifecycle

Дата: 27 октября 2026 года. Ветка codex/mod-amqp-filter-engine-stage3, HEAD
7d8d9e948b6761a8ec8a8672009d9051cf27cb8a. **Вердикт: стандартный
load/unload пока не реализован; BLOCKED на контракте Core loader.**
Production C-код, Core, установленный модуль и рабочая конфигурация в этом
этапе не менялись. Операций над работающим FreeSWITCH/RabbitMQ не было.
SHA-256 используемой установленной libfreeswitch.so:
85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145.

Исходный tracked diff и 24 относящихся к hardening новых текстовых файла
сохранены в [permanent-baseline.patch](standard-lifecycle-artifacts/permanent-baseline.patch)
(SHA-256 6227422e8bf957053167a37c6045f242b233d6fd8e4f25d37db52191de882e4d).
[Manifest SHA-256](standard-lifecycle-artifacts/permanent-baseline.sha256) и
[исходный status](standard-lifecycle-artifacts/permanent-baseline-status.txt)
сохраняют HEAD, ветку и перечень файлов. Генерированные бинарники и журналы
не включены в patch, но остаются в прежних каталогах. Применимых AGENTS.md не
найдено. Исправления синхронизации command/logging, зависимости сборки,
worker-loop tests, API-ответ и health-диагностика сохранены.

## Модель других модулей

| Модуль | Реальный порядок и полезный приём | Ограничение |
| --- | --- | --- |
| [mod_event_socket](../../src/mod/event_handlers/mod_event_socket/mod_event_socket.c#L577) | Помечает done, закрывает listening socket для пробуждения accept/recv, ждёт listeners, снимает removable event binding. [Load](../../src/mod/event_handlers/mod_event_socket/mod_event_socket.c#L1180) регистрирует binding перед API. | Shutdown ограничивает ожидание счётчиком и затем возвращает SUCCESS; результат unbind не проверяется. Это не доказательство отсутствия живых ссылок. |
| [mod_event_multicast](../../src/mod/event_handlers/mod_event_multicast/mod_event_multicast.c#L910) | Ставит running=0, снимает event callback, ждёт runtime loop; [cleanup](../../src/mod/event_handlers/mod_event_multicast/mod_event_multicast.c#L242) закрывает UDP sockets. [Load](../../src/mod/event_handlers/mod_event_multicast/mod_event_multicast.c#L853) имеет общий fail label. | Fail label освобождает subclasses, но не всю инициализированную сеть; ожидание runtime — polling, без проверяемого join результата. |
| [mod_sofia](../../src/mod/endpoints/mod_sofia/mod_sofia.c#L6838) | Partial-load вызывает тот же shutdown cleanup. [Cleanup](../../src/mod/endpoints/mod_sofia/mod_sofia.c#L6844) снимает callbacks, посылает NULL и interrupt_all в очереди, затем join рабочих потоков. | Есть ограниченное ожидание части threads и игнорируемые результаты join; переносить это как гарантию безопасности нельзя. |

Применимая схема: запретить новую работу, снять callback bindings как барьер,
пробудить queue/sleep, дождаться каждого join, закрыть connection и лишь затем
уничтожить очередь, hash и pool. Свойства Core loader надо проверить отдельно:
удачный порядок внутри модуля не исправляет решение Core удалить interfaces
до вызова shutdown.

## Контракты отказов и ожидания

| Операция | Реальный контракт и классификация |
| --- | --- |
| [switch_event_unbind()](../../src/switch_event.c#L2175) | При действующем собственном node и работающем event engine берёт write RWLOCK, удаляет node и обнуляет handle; [delivery](../../src/switch_event.c#L400) держит read RWLOCK на время callback. NULL/отсутствующий node даёт FALSE: обычно ошибка владения, конкурентный destroy или искусственная fault injection, а не нормальный отказ сети. Нельзя вызывать unbind из event callback (upgrade read→write). |
| [switch_thread_join()](../../src/switch_apr.c#L1379) | Проверяет NULL, затем делегирует APR. Для корректности нужны joinable handle, один владелец, отсутствие self-join и отсутствие конкурентного освобождения pool. Ошибка APR/OS возможна, но её нельзя игнорировать или освобождать DSO при ещё живом потоке. Self-join command worker — достижимое нарушение контекста, описано ниже. |
| [switch_queue_pop_timeout()](../../src/switch_apr_queue.c#L1248) | Producer/logging ждут до 1 s; [queue implementation](../../src/switch_apr_queue.c#L307) возвращает timeout/EINTR/EOF. [interrupt_all](../../src/switch_apr_queue.c#L1269) будит pop без уничтожения очереди; queue_term выставляет terminated под mutex. Текущий mod_amqp не посылает interrupt; это задержка shutdown, не основание освобождать pool раньше join. |
| Reconnect sleep | Producer [656](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L656), command [325](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L325), logging [388](../../src/mod/event_handlers/mod_amqp/mod_amqp_logging.c#L388) используют switch_sleep с конфигурируемым reconnect_interval_ms без немедленного wakeup. Долгая настройка может задержать join; это штатный внешний сценарий. |
| Connect/login/RPC | Текущий [connection_open](../../src/mod/event_handlers/mod_amqp/mod_amqp_connection.c#L130) вызывает блокирующий amqp_socket_open. В контейнере установлена rabbitmq-c 0.11.0 (pkg-config; DSO использует /lib/x86_64-linux-gnu/librabbitmq.so.4): /usr/include/amqp.h:2350–2369 предлагает amqp_socket_open_noblock с timeout; :2452–2477 — handshake timeout (default 12 s); :2508–2535 — RPC timeout, по умолчанию бесконечный. Версия хоста 0.16.0 для этих выводов не использовалась. Отдельные RPC exchange/queue/channel и [connection_close](../../src/mod/event_handlers/mod_amqp/mod_amqp_connection.c#L40) могут ждать broker. Недоступный или зависший broker — внешний отказ; лимиты ещё не реализованы и не подтверждены сетевым probe. |
| Consume/frame/publish | [Command consume](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L433) задаёт 500 ms, но ветка unexpected state вызывает [amqp_simple_wait_frame](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L439) без timeout; /usr/include/amqp.h:1487–1551 предоставляет вариант _noblock. Producer [publish](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L591), logging [publish](../../src/mod/event_handlers/mod_amqp/mod_amqp_logging.c#L321) и command response [publish](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L277) исполняются в worker; документация rabbitmq-c указывает, что возврат publish означает передачу, а не broker confirmation. Ограничение socket write/TLS и DNS ещё не доказано. Закрывать тот же connection из другого потока без подтверждённой thread safety нельзя. |

Текущие profile stop flags command/logging уже синхронизированы. Для
producer-owned bindings, queue и pool соблюдается правило unbind → stop → join
→ free в [producer_destroy](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L137).
Initial activation с частичным bind вызывает cleanup; успешный cleanup
возвращает обычную ошибку, retained owner сохраняет DSO. Это защита памяти при
fault injection, но не гарантия безопасного повторного Core unload.

## Предложенный порядок штатной остановки до изменения кода

1. Core должен исключить reentrant/self unload и гарантировать, что module
   interfaces сохраняются до успешного shutdown либо что shutdown не может
   отказать после unprocess. Для данного Core этот precondition не выполнен.
2. Под единственным lifecycle owner выставить closing, прекратить новые
   config operations. Снять все producer bindings и logger callback; после
   успешного unbind больше нет новых callback, текущие завершились.
3. Под profile mutex установить stop flags, разбудить queue waits через
   interrupt_all и заменить длинные reconnect sleeps на прерываемое ожидание.
   Не держать lifecycle/profile mutex через unbind, AMQP I/O или join.
4. До join доказать конечность connect/login/RPC/consume/publish/close на
   используемой rabbitmq-c и контролируемом broker; timeout не должен менять
   подтверждение доставки. Дождаться producer, command и logging workers.
5. Только после join закрывать их connection на том же owner path, опустошать
   очереди, удалять hash entries и pools. Возвращать SUCCESS только если
   callbacks и workers действительно завершены. Частичный initial load
   проходит тот же unwind до возврата ошибки.

Это проект порядка, **не реализованный контракт**. Его нельзя безопасно
внедрить отдельными timeout/wakeup правками, пока остаётся Core blocker ниже.

## Достижимый blocker в Core

[Core unload_module](../../src/switch_loadable_module.c#L1889) сначала удаляет
module_hash entry. Для forced unload он вызывает [do_shutdown](../../src/switch_loadable_module.c#L2335)
с fail_if_busy=false. Тот помечает shutting_down, вызывает
[switch_loadable_module_unprocess](../../src/switch_loadable_module.c#L1103),
удаляющую API/interface hashes, **до** mod_amqp_shutdown; возвращённый
NOUNLOAD удерживает DSO, но do_shutdown всё равно возвращает SUCCESS. Поэтому
ошибка shutdown после начала Core teardown не может восстановить registry/API
из mod_amqp. Обратный SUCCESS при живом worker опаснее: Core освободит DSO/pool.

Это не только искусственный отказ unbind. [Изолированный probe](standard-lifecycle-artifacts/forced-busy-main.c)
использовал production DSO, скопированный в отдельный каталог с **единственным**
изменением успешного load NOUNLOAD→SUCCESS ([diff](standard-lifecycle-artifacts/nonpermanent-variant.patch)).
Interposer [лишь удерживал unbind](standard-lifecycle-artifacts/forced-busy-interposer.c),
пока параллельный api amqp владел lifecycle mutex; сам unbind потом вернул
обычный результат. В этом окне forced unload — штатный API Core —
обходит busy-check. [Журнал](standard-lifecycle-artifacts/forced-busy.log):
load=0, forced_unload=0 (Core сообщает успех), exists=1 (FALSE),
status_before=1, status_after=0, dso_resident=1, параллельный config reload
завершился +OK. Процесс probe exit 0 означает воспроизведение несогласованного
состояния, **не** успешную приёмку. Это достижимая гонка управления; задержка
unbind в probe лишь делает окно детерминированным, ошибки unbind не вводились.

Есть более фундаментальный self-unload path: [command worker](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L505)
передаёт произвольную строку в [switch_console_execute()](../../src/switch_console.c#L345),
тот вызывает switch_api_execute(), а команда [unload mod_amqp](../../src/mod/applications/mod_commands/mod_commands.c#L2737)
вызывает Core unload **на том же command worker**. Текущий
[mod_amqp_shutdown()](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L151)
обнаруживает этот thread и возвращает NOUNLOAD; Core уже удалил interfaces.
Если вместо этого выполнить join собственного worker — deadlock; вернуть
SUCCESS до выхода worker — unload DSO с текущим стеком внутри DSO. Простая
замена trylock на блокирующий lock исправила бы лишь один race, не self-unload
и не отказ Core после unprocess. Запрет одного буквального текста команды
не охватит aliases и другие API, которые вызывают unload.

Следовательно, без поддерживаемого Core veto/rollback **или**
существенного изменения контракта произвольного command execution в mod_amqp
нельзя доказать штатный unload во всех достижимых контекстах. По условию
задания реализация standard load/unload на этом этапе остановлена. Никакой
обходной permanent-правки не внесено: текущий рабочий код по-прежнему содержит
предыдущую permanent-политику, сохранённую отдельным patch. Для обычной
динамической модели потребуется отдельно согласовать изменение Core или
ограничение/перепроектирование command ingress, затем повторить исследование
network deadlines.

## Проверки и границы результата

[Контрольный probe](standard-lifecycle-artifacts/standard-cycle-main.c) с
той же one-line nonpermanent копией выполнил три обычных цикла
load→unload с кодами 0; после каждого registry/API отсутствовали, затем
следующая загрузка прошла. [Журнал](standard-lifecycle-artifacts/standard-cycle.log),
exit 0. Это подтверждает штатный путь без конкуренции, не универсальную
безопасность. Оба probe и копия DSO собраны с -Wall -Werror против
/usr/local/freeswitch/lib/libfreeswitch.so в отдельных процессах. Точный
[скрипт воспроизведения](standard-lifecycle-artifacts/run-probes.sh) завершился
с exit 0; [общий журнал](standard-lifecycle-artifacts/probe-run.log). Они не
устанавливались.

Для неизменённого production дерева ранее выполнены
[make -Werror и regression](hardening-artifacts/check-permanent-v2.log),
exit 0: 19/19 engine, 18/18 lifecycle, 37/37 integration; в них есть
legacy/rules, matcher до JSON, routing, publish и API +OK/-ERR.
[Dependency probe](hardening-artifacts/dependency-permanent-summary.log)
exit 0. [Engine sanitizers](hardening-artifacts/sanitizer-engine-policy-final-summary.log)
ASan+UBSan+LSan и TSan прошли; [integration sanitizer](hardening-artifacts/sanitizer-policy-v2-run.log)
TSan 37/37 прошёл, ASan+UBSan+LSan exit 1 в sigaltstack при APR thread exit.
Причина не доказана, проверки не отключались; инструментированы тестовые
translation units/proxy, но не libfreeswitch/librabbitmq. Новые
shutdown/network/loaded-Core-process sanitizer tests не выполнялись:
реализация остановлена на воспроизведённом Core blocker. Нельзя считать
выход процесса доказательством cleanup.

Проверочный build-tree модуль не установлен. Ранее проверенный установленный
mod_amqp.so имел SHA-256
31b8dba5b522808a1bc95f07ccde8b332eaca9e4d2432899ec9d48bfbc583d1f;
новый isolated DSO лежит только в
[probe-bin](standard-lifecycle-artifacts/nonpermanent-bin/).
Надёжность доставки RabbitMQ и publisher confirms не исследовались.
