# Проверка load/unload исходного `mod_amqp` до Filter Engine

Дата: 27 октября 2026 года. Исходник взят **из ветки `develop`**, commit
`0cf10d65bdd1d32e30b749a785573da322bde708`. Содержимое
`src/mod/event_handlers/mod_amqp` на `develop` совпадает с commit
`1ff547f988186de7f1903eba16d5477cde72e27d` перед первым этапом наших
изменений (`git diff --exit-code develop 1ff547f988 -- src/mod/event_handlers/mod_amqp`:
exit 0). Текущая ветка `codex/mod-amqp-filter-engine-stage3` и её незакоммиченная
работа не переключались и не менялись. Снимок исходника получен через
`git archive develop` в [каталог пробы](prechange-load-unload-artifacts/).

## Результат

| Сценарий | Результат |
| --- | --- |
| Три последовательных `load → API amqp (reload) → unload` с producer `event_filter=DTMF,CUSTOM` | [exit 0](prechange-load-unload-artifacts/cycle.log). Каждый load/reload/unload вернул `SWITCH_STATUS_SUCCESS` (`0`); после unload `switch_loadable_module_exists` вернул `1` (`SWITCH_STATUS_FALSE`), интерфейс `amqp` отсутствовал. Между операциями доставлялся DTMF; после unload также доставлялся DTMF. |
| Те же три цикла с `force=SWITCH_TRUE` при unload | [exit 0](prechange-load-unload-artifacts/forced-cycle.log), те же статусы. Конкурентной работы при forced unload не было. |
| Ошибка второго `switch_event_bind_removable()` при создании producer | [exit 0](prechange-load-unload-artifacts/bind-fault.log) у диагностической проверки состояния: `binds=2`, `individual_unbinds=0`, `global_unbinds=0` после load, при этом Core считает модуль загруженным. При последующем unload вызван один глобальный unbind. Это **дефект исходного lifecycle**, а не успешная проверка очистки. |

Сборка исходного DSO и диагностических программ выполнена в контейнере
`freeswitch-dev` с `-Wall -Werror` против установленной
`/usr/local/freeswitch/lib/libfreeswitch.so`. Пробы запускались в собственных
процессах Core с отдельным [freeswitch.xml](prechange-load-unload-artifacts/conf/freeswitch.xml),
без подключений к RabbitMQ. Исходный DSO лежит только в
[bin/mod_amqp.so](prechange-load-unload-artifacts/bin/mod_amqp.so), SHA-256
`735a6e3cc2c096758bea7c4b06acffcff4fbe25e68b0c0d1b7b8703c9ee3fd91`.
Установленный модуль остался с SHA-256
`31b8dba5b522808a1bc95f07ccde8b332eaca9e4d2432899ec9d48bfbc583d1f`.
Работающий FreeSWITCH, его конфигурация и RabbitMQ не трогались.

## Почему частичная ошибка опасна

Исходный [producer_create](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L352)
регистрирует bindings по одному и при ошибке переходит к `err`. Там вызывается
[producer_destroy](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L374),
но [destroy](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L115)
не снимает event bindings, после остановки sender освобождает pool профиля.
Таким образом первый успешный binding сохраняет указатель на уничтоженный профиль
до глобального `switch_event_unbind_callback()` при
[unload](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp.c#L87)
или [reload](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L100).
Кроме того, [do_config](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L125)
только логирует отказ создания профиля и возвращает `SUCCESS`; поэтому
[mod_amqp_load](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp.c#L71)
публикует API и успешно завершается. Доставка подходящего события в этом окне
может обратиться к освобождённому профилю. Проба намеренно **не доставляла**
событие после fault injection, чтобы не превращать проверку в аварийное падение.

При первом варианте fault probe после штатного unload вызов
`switch_core_destroy()` не завершился за 12 секунд (`timeout` exit 124;
[журнал](prechange-load-unload-artifacts/bind-fault-line.log)). Это наблюдение
получено с `LD_PRELOAD` interposer и не позволяет отдельно установить причину
зависания Core; окончательная fault probe завершает только процесс проверки
после контроля глобального unbind. В обычных и forced циклах
`switch_core_destroy()` завершился успешно.

## Границы вывода

Последовательный load/unload исходной версии **работает** в проверенной
конфигурации, но это не гарантия безопасного unload при параллельном callback,
reload, блокирующем AMQP I/O или command/logging worker. Исходный
[producer_destroy](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L129)
пишет `running=0` и ждёт sender, а
[producer_thread](prechange-load-unload-artifacts/src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L450)
читает флаг без синхронизации. Глобальный unbind применяется ко всем producer
callbacks сразу и не обеспечивает очистку при частичной ошибке до reload/unload.
В проверенной конфигурации не было AMQP connections, поэтому доставка в RabbitMQ
и остановка блокирующего сетевого вызова не проверялись.

Диагностические исходники:
[обычные/forced циклы](prechange-load-unload-artifacts/prechange-cycle-main.c),
[частичная ошибка](prechange-load-unload-artifacts/bind-fault-main.c) и
[interposer](prechange-load-unload-artifacts/bind-fault-interposer.c).
