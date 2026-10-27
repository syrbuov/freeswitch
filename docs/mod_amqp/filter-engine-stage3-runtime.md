# mod_amqp Filter Engine v1 — runtime-проверка этапа 3

Дата: 27 октября 2026 года. Ветка: `codex/mod-amqp-filter-engine-stage3`.
Дополнение к [отчёту реализации](filter-engine-stage3.md), составленному до
разрешения установки модуля в работающий контейнер.

## Результат

Фильтрация, сохранение работающих producer-профилей при ошибке подготовки,
config reload и unload/load модуля проверены с настоящими FreeSWITCH и RabbitMQ.
Реальный звонок с двумя ногами завершился успешно; все восемь ожидаемых
публикаций получены без дубликатов. После отключения брокера FreeSWITCH продолжил
работу, producer автоматически переподключился и возобновил фильтрацию.

**Доставка без потерь при отказе брокера не подтверждена: тест не пройден.**
Из двух разрешённых событий, созданных во время отключения, получено одно.
Ограничение транспорта и границы диагностики описаны ниже. Этот результат
не следует заменять формулировкой «все runtime-тесты прошли».

## Среда и установка

- FreeSWITCH: контейнер `freeswitch-dev`, исходники `/usr/src/freeswitch` из volume.
- RabbitMQ: контейнер `rabbitmq`; проверялся существующий vhost `/`.
- Рабочий XML: `/etc/freeswitch/autoload_configs/amqp.conf.xml`, volume из
  `/root/ray-tech/freeswitch/freeswitch-dev/autoload_configs/amqp.conf.xml`.
- Установленная библиотека Core:
  `/usr/local/freeswitch/lib/libfreeswitch.so.1.0.0`, ревизия `82bf16a286`.
- Исходный HEAD репозитория: `7d20cfbdb75bf62756a8d835c106f0c569bd048f`.

Сборка выполнена внутри `freeswitch-dev`, из каталога модуля:

```sh
make -j2 mod_amqp.la \
  mod_amqp_la_LIBADD="-L/usr/local/freeswitch/lib -lfreeswitch" \
  mod_amqp_la_LDFLAGS="-avoid-version -module -no-undefined -shared -lrabbitmq -Wl,-z,defs -Wl,-rpath,/usr/local/freeswitch/lib"
```

Установлен только `.libs/mod_amqp.so` в `/usr/local/freeswitch/mod/mod_amqp.so`.
Использована временная копия с последующим rename. Корневой
`make mod_amqp-install` не запускался: в дереве присутствует ранее собранный
другой Core, который нельзя устанавливать поверх работающего сервиса.
Core и исходники C в рамках этой runtime-проверки не изменялись.

SHA-256 установленного модуля:
`2e3ce5943c029965ab32e43701b4f9243b51f65b598fcd28634d020184a812a8`.
SHA-256 установленного Core до и после установки/reload:
`85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145`.

В `freeswitch-dev:/tmp/mod-amqp-runtime-stage3/` сохранены исходные
`amqp.conf.original.xml`, `mod_amqp.original.so`, `core-before.sha256`,
`build.log`, журналы full reload и вспомогательные скрипты. XML содержит
параметры подключения и не включён в репозиторий.

## Метод наблюдения

Созданы отдельные очереди `codex.stage3.observe.tap`, `.control`, `.probe`,
`.logging`, привязанные соответственно к `TAP.Events`, `OSYRBU.Events`,
`Codex.Filter.Stage3`, `TAP.Logging`. Сообщения приложения не потреблялись
и его очереди не очищались. Наблюдатель читал только собственные очереди.

Для сравнения `default` временно переведён в rules с четырьмя событиями звонка;
`osyrbu` оставлен в legacy с `SWITCH_EVENT_ALL`. Временный producer
`codex-filter-probe` отправлял CUSTOM в отдельный exchange. События создавались
настоящей ESL-командой `sendevent`, а проверялся результат публикации в RabbitMQ.

Сохранялись выбранные заголовки: Event-Name, Event-Subclass, Event-Sequence,
Unique-ID, идентификаторы связи ног, время, результат завершения, тестовые
Codex-Probe/Codex-Probe-ID, routing key и признак redelivered. Полные тела
звонков, телефонные номера, содержимое логов и пароли в выборку не записывались.
Для логов сохранялся boolean наличия тестового маркера.

## Проверенные сценарии

В каждой синтетической серии отправлялись пять CUSTOM-событий: два разрешённых,
одно с неверным значением заголовка, одно с другим subclass и одно без заголовка.
Условия разрешения: Event-Subclass равен `codex::filter_stage3` **и**
Codex-Probe равен `allow`.

| Серия | Контрольный legacy producer | Rules producer | Результат |
| --- | ---: | ---: | --- |
| `specific`: два одинаковых CUSTOM-правила | 5 | 2 | Каждое разрешённое событие опубликовано один раз |
| `invalid-retains`: неизвестный mode последнего producer при config reload | 5 | 2 | Ошибка подготовки сохранила старые работающие профили |
| `mixed`: CUSTOM-правило и правило без selectors, оба совпадают | 5 | 2 | Общая подписка не дала двойной публикации |
| `deny`: пустой rules filter | 5 | 0 | Deny all |
| `outage-before`: перед отключением RabbitMQ | 5 | 2 | Контрольная доставка работает |
| `outage-after`: после автоматического reconnect | 5 | 2 | Фильтрация и доставка новых событий восстановлены |

Для конфигурационного reload вызывались `fs_cli -x reloadxml`, затем
`fs_cli -x amqp`. Для unload/load использовалась `fs_cli -x "reload mod_amqp"`;
CLI подтвердил `module unloaded` и `module loaded`. Ошибочный XML проверялся
через config reload, **не** через выгрузку модуля: это разные гарантии lifecycle.
Публикация тестовых логов подтверждена после config reload, full reload и
восстановления брокера.

Проверка соответствует реальным путям
[`mod_amqp_do_config()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L175),
[`mod_amqp_producer_prepare()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L215),
[`mod_amqp_producer_activate()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L459)
и [`mod_amqp_producer_event_handler()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L87).

### Ответ API reload

Обнаружена неоднозначность CLI-ответа, требующая отдельного улучшения диагностики.
[`amqp_reload()`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L47)
возвращает status, но не пишет текст в stream. Поэтому успешный config reload
через ESL отображается как `-ERR no reply`, а ошибка подготовки — как
`-ERR amqp Command not found!`, хотя API зарегистрирован.
Это следует из обработки status и пустого stream в
[`mod_event_socket.c`](../../src/mod/event_handlers/mod_event_socket/mod_event_socket.c#L1552).
Exit code `fs_cli` сам по себе также не является проверкой успеха reload.

Успешность здесь установлена по изменению фактических публикаций, а отклонение
неверного mode — по журналу подготовки и сохранению прежней фильтрации.
Core не исправлялся. Рекомендуется отдельное изменение ответа `amqp_reload()`
в модуле с проверкой через ESL; в данном прогоне исходники не менялись.

## Реальный звонок

Пользователь выполнил звонок, соединил обе ноги и подтвердил успешное завершение.
Наблюдатель получил следующие события в `TAP.Events`:

| Событие | Число публикаций | Event-Sequence |
| --- | ---: | --- |
| CHANNEL_CREATE | 2 | 1234, 1250 |
| CHANNEL_PROGRESS | 2 | 1245, 1254 |
| CHANNEL_ANSWER | 2 | 1258, 1271 |
| CHANNEL_HANGUP_COMPLETE | 2 | 1310, 1319 |

Множества `(Unique-ID, Event-Name, Event-Sequence)` совпали с соответствующей
выборкой контрольного legacy producer. Каждая тройка встретилась ровно один раз
в каждом профиле, redelivered=false. Другие события этих ног в rules producer
не прошли, хотя контрольный профиль получил, например, CHANNEL_STATE,
CHANNEL_EXECUTE, CHANNEL_BRIDGE и CHANNEL_DESTROY. Обе ноги завершились с
`NORMAL_CLEARING`, затем `show channels count` вернул `0 total`.
Сохранён машинно проверенный результат `call-check.json` в каталоге наблюдателя.

## Отключение RabbitMQ и обнаруженная потеря

После завершения звонка создана отдельная **durable**-очередь
`codex.stage3.outage`, привязанная к тестовому exchange. Контрольные сообщения
до отказа были получены и удалены из этой очереди. Далее выполнены
`docker stop -t 15 rabbitmq`, отправка серии `outage-down`, `docker start rabbitmq`.
Модуль в интервале отказа/reconnect не перезагружался.

FreeSWITCH отвечал через ESL и оставался с нулём активных каналов.
RabbitMQ понадобилось около 28,5 секунд для запуска; ранняя проверка readiness
и первый запрос management API не прошли, повторная проверка выполнена после
завершения запуска. Producer, command и logging connections восстановились.

Из разрешённой пары получен только `outage-down-allow-2` (Event-Sequence 1347),
redelivered=false. `outage-down-allow-1` не получен ни при первом успешном
чтении, ни при последующей проверке очереди. После восстановления новые
`outage-after-allow-1` и `outage-after-allow-2` получены по одному разу
(Event-Sequence 1360 и 1363). Запрещённые сообщения в этой очереди отсутствуют.

В журнале в 09:54:50 по времени FreeSWITCH зарегистрирована ошибка отправки
`Profile[codex-filter-probe] failed to send event` и дальнейшие reconnect.
Успешный запуск брокера завершился около 09:55:32 по Москве.

[`mod_amqp_producer_send()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L591)
вызывает `amqp_basic_publish()` без publisher confirms. Неотрицательный результат
считается успехом, после чего
[`mod_amqp_producer_thread()`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L670)
освобождает сообщение. Подтверждение принятия сообщения брокером не ожидается.
Обе функции побайтово совпадают с HEAD этапа 2.

**Вывод из кода:** существующий transport допускает потерю на границе разрыва
соединения; успешная локальная отправка не означает подтверждённую брокером
доставку. Наблюдение согласуется с этим ограничением. Точный результат
`amqp_basic_publish()` для каждого из двух сообщений не трассировался,
поэтому конкретный механизм потери остаётся гипотезой. Проверка старой версии
модуля при таком же отказе не выполнялась.

Durable-очередь пережила restart и имела binding заранее, поэтому исчезновение
обычных недолговечных наблюдательных очередей не объясняет результат этого теста.
Обычные очереди наблюдения и их процесс после restart были созданы повторно.
Publisher confirms/retry/deduplication требуют отдельной задачи изменения
транспорта. Гарантия одного прохода rules на профиль не является гарантией
exactly-once или отсутствия потерь при сетевом отказе.

## Оставшиеся проверки и границы

- Нет длительного нагрузочного прогона, массового переполнения send queue,
  сетевого blackhole, reload во время активного звонка или отказа брокера.
- Нет проверки graceful shutdown всего FreeSWITCH под нагрузкой и живых
  инъекций allocation/bind/join failures; соответствующие тестовые инъекции
  описаны отдельно в отчёте реализации.
- Санитайзеры не подключались к работающему FreeSWITCH. Эта проверка не доказывает
  отсутствие всех гонок, deadlock и use-after-free; ограничения command/logging
  workers из основного отчёта сохраняются.
- Второй реальный звонок после restart RabbitMQ не выполнялся; восстановление
  подтверждалось публикациями и подключениями, не повторным call-control тестом.
- Полное содержимое JSON не сравнивалось побайтово. Проверены выбранные поля,
  routing keys и поведение внешнего приложения во время звонка.

## Итоговое состояние

Исходный XML восстановлен побайтово: SHA-256 рабочего файла после восстановления
`d81022edc64b75ec784e18b5408876901dba0b81fcb761495af414077e7f851a`.
Повторный full reload модуля завершился успешно. В проверочной серии
`restored-legacy` каждый из штатных профилей `default` и `osyrbu` опубликовал
все пять CUSTOM-событий; временного rules producer больше нет.
`module_exists mod_amqp` вернул `true`, `show channels count` — `0 total`.

Наблюдатель остановлен. Удалены только пять созданных для проверки очередей
`codex.stage3.*` и exchange `Codex.Filter.Stage3`; очереди и exchanges
приложения не удалялись. RabbitMQ оставлен работающим. **Собранный модуль
этапа 3 остаётся установленным**. Его исходный `.so` сохранён в резервной копии.

Резервные копии и runtime-артефакты остаются в
`/tmp/mod-amqp-runtime-stage3/` соответствующих контейнеров; они не переживут
удаление контейнеров. Секреты в отчёт не включены.
