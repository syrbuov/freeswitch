# Повторная диагностика mod_amqp в свежем Docker-контейнере

Дата: 26 октября 2026 года. Ветка: `codex/mod-amqp-producer-lifecycle`.
Проверены текущие незакоммиченные изменения этапа producer lifecycle.

## Результат

**Сообщённый SIGSEGV не воспроизведён.** Чистая сборка модуля, 18/18
lifecycle-тестов и восемь полных `reload mod_amqp` прошли успешно.
Во время reload процесс находился под GDB с остановкой на SIGSEGV;
таких остановок не было. Три reload выполнены параллельно с подачей событий.

**Подтверждена отдельная проблема окружения:** корневая команда
`make mod_amqp-install` устанавливает также Core. В volume сохранилась
библиотека Core старее библиотеки свежего образа. Команда заменяет свежую
библиотеку на диске этой старой копией. Это создаёт несогласованное окружение,
но не доказывает причину прежнего падения: его backtrace отсутствует.

После проверки исходная библиотека свежего образа восстановлена, GDB отключён.
FreeSWITCH отвечает на `status`, `module_exists mod_amqp` возвращает `true`.
Новых изменений C-кода, конфигурации и файлов сборки во время этой диагностики
не внесено.

## Проверенная среда

| Объект | Фактическое значение |
| --- | --- |
| Контейнер | `freeswitch-dev`, ID начинается с `59fd08c96ad9` |
| Образ | `freeswitch-local-dev:mod_speechkit_vscode` |
| Начало работы контейнера | `2026-10-26T11:19:52.808831414Z` |
| Mount проекта | `/root/freeswitch-devcontainer/freeswitch-develop` → `/usr/src/freeswitch` |
| Процесс | FreeSWITCH, PID 1, на проверке активных звонков не было |
| Свежий установленный Core | `1.10.13-dev git 82bf16a`, `2025-10-08 13:01:53Z` |
| Core из volume `.libs` | `1.10.13-dev git ae5ffee`, `2025-01-10 12:25:14Z` |
| RabbitMQ C library для сборки | `0.11.0` |
| Текущие producers | `default`, `osyrbu`; у обоих `event_filter=SWITCH_EVENT_ALL` |

Пересоздание контейнера обновило его установленный Core, но сохранило
артефакты сборки в подключённом volume. Поэтому эти два источника библиотек
проверялись раздельно. Сборка всего Core не выполнялась.

## Сборка и lifecycle-тесты

Сначала проверена установка из каталога модуля. Затем выполнена чистая
пересборка всех шести исходников модуля и установка:

```sh
cd /usr/src/freeswitch/src/mod/event_handlers/mod_amqp
make clean
make -j2 install
```

Сборка прошла со штатным `-Werror`, без подавления предупреждений.
Хеш установленного Core до и после этой команды совпал.

Обычный `make check` прошёл. Дополнительно тестовый executable пересобран
с явной линковкой к свежему установленному Core, чтобы исключить запуск
тестов только со старой библиотекой из volume:

```sh
timeout 90s make -j2 check \
  test_test_producer_lifecycle_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq" \
  test_test_producer_lifecycle_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib"
```

Перед этой проверкой удалены предыдущий тестовый executable и его object
files. Это разовое переопределение параметров команды, файлы сборки ради
выбора библиотеки не редактировались.

Результат тестового журнала:

```text
PASSED (18/18 tests in 0.037002s)
PASS test/test_producer_lifecycle (exit status: 0)
```

Automake показывает `TOTAL: 1, PASS: 1`: зарегистрирован один executable,
внутри которого находятся 18 test cases. Регистрация:
[`Makefile.am:12`](../../src/mod/event_handlers/mod_amqp/Makefile.am#L12).

Проверены, в частности:

- Независимость профилей, legacy-дубли, ALL/пустой фильтр/CUSTOM subclass.
- Duplicate name и защита чужой записи hash.
- Отказ первого, второго и третьего bind с очисткой уже созданных подписок.
- Ошибки mutex/queue/hash/thread creation, включая недействительные выходные
  handles после ошибочного create API.
- Ошибка аварийной очистки при частичном create: профиль остаётся доступен
  через hash; последующая очистка успешна.
- Отказ unbind/join с сохранением ресурсов и повторной очисткой.
- Ожидание выполняющегося callback и ещё не завершившегося sender.
- Concurrent/reentrant reload, отказ reload из command worker.
- Повторный reload, остановка на teardown failure, индивидуальное снятие
  bindings при shutdown и `NOUNLOAD` при ошибке join.

Реальные event engine, bindings, unbind, pools, queues и join используются
в [`test_producer_lifecycle.c`](../../src/mod/event_handlers/mod_amqp/test/test_producer_lifecycle.c).
Сетевой sender в этих тестах заменён joinable test worker; это не проверка
доставки в RabbitMQ.

## Проверка реального процесса под GDB

GDB подключён к PID 1; настроены `SIGPIPE nostop noprint pass` и
`SIGSEGV stop print nopass`. Последовательно выполнены:

| Проверка | Результат |
| --- | --- |
| Четыре полных reload после первоначальной установки | Успешно |
| Три полных reload после чистой сборки, параллельно с событиями | Успешно |
| Один полный reload после точной команды `make mod_amqp-install` из корня | Успешно |

Каждый reload ответил:

```text
+OK Reloading XML
+OK module unloaded
+OK module loaded
```

Параллельный probe через локальный ESL подал **1284 CUSTOM-события** с
`Event-Subclass: mod_amqp::lifecycle_probe`. ESL подтвердил приём всех событий;
ошибок отправки или reload не зарегистрировано. Оба producer подписаны на ALL.
Это проверяет reload при поступлении событий, но не гарантирует, что каждое
событие сериализовано, опубликовано или доставлено потребителю: при reload
сохраняются прежние окна без подписок и удаление оставшихся очередей.

GDB не зафиксировал SIGSEGV. По завершении debugger отсоединён;
`/proc/1/status` показывает `TracerPid: 0`, процесс продолжает работать.

## Почему корневой install меняет Core

В [`Makefile.am:31`](../../Makefile.am#L31) обработчик `.DEFAULT` разбирает
суффикс цели. Для `*-install` он явно вызывает `core_install`, затем передаёт
цель в `src/mod` — см. [`Makefile.am:51`](../../Makefile.am#L51).
`core_install` ведёт к `install-libLTLIBRARIES`:
[`Makefile.am:680`](../../Makefile.am#L680).

В логе фактического `make mod_amqp-install`:

```text
libtool: install: /usr/bin/install -c .libs/libfreeswitch.so.1.0.0 /usr/local/freeswitch/lib/libfreeswitch.so.1.0.0
```

SHA-256 `/usr/local/freeswitch/lib/libfreeswitch.so.1.0.0`:

| Момент | SHA-256 |
| --- | --- |
| Свежий образ, до установки | `85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145` |
| После установки только из каталога модуля | `85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145` |
| После корневого `make mod_amqp-install` | `1e7f38c63165b17eea20e686de57f226c38c825e5541bb5c18f9e6a83275c035` |
| После восстановления резервной копии | `85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145` |

Третий хеш совпадает с `/usr/src/freeswitch/.libs/libfreeswitch.so.1.0.0`.
Версии подтверждены строками обеих библиотек. Метаданные установленного
`libfreeswitch.la` после проверки совпадают с исходным образом:
`c28d1e138a128ab347f88a7a5db9b377f924224af7ff0664305fddff522618d0`.

Замена файла на диске не означает, что текущий процесс немедленно начал
исполнять новый Core. Успешный reload в этом процессе не подтверждает
работоспособность следующего запуска с подменённой библиотекой. Перезапуск
процесса со старой библиотекой в этой проверке не выполнялся.

Для последующей установки только модуля в проверенном окружении:

```sh
make -C /usr/src/freeswitch/src/mod/event_handlers/mod_amqp -j2 install
fs_cli -H 127.0.0.1 -P 8021 -x "reload mod_amqp"
```

Эта команда обходит корневой `core_install`. При этом модуль по-прежнему
линкуется через build-tree `libfreeswitch.la`, как задано в
[`Makefile.am:9`](../../src/mod/event_handlers/mod_amqp/Makefile.am#L9).
Она не решает общего вопроса согласования headers, build artifacts и Core
образа. Для воспроизводимой разработки их нужно привести к одной версии;
пересборка/замена Core выходит за пределы текущей задачи.

## Артефакты и оставшиеся ограничения

Журналы текущей диагностики и резервные копии оставлены в контейнере в
`/tmp/mod-amqp-fresh-diag/`: `rebuild-install.log`, `lifecycle-fresh-core.log`,
`concurrent-probe.json`, `gdb.txt`, `root-target-install.log`,
`root-target-reload.txt`, исходные `.so`. Они исчезнут при пересоздании
контейнера. Основные результаты и хеши сохранены выше.
Журнал 18 тестов находится в
`src/mod/event_handlers/mod_amqp/test/test_producer_lifecycle.log`.

- Backtrace исходного пользовательского падения не получен. Нельзя объявить
  исправленной его первопричину или исключить редкую гонку по этим прогонам.
- ASan/UBSan/TSan, длительный stress, реальные звонки, broker disconnect и
  длительно заблокированный сетевой sender не проверялись.
- Нет проверки end-to-end доставки RabbitMQ и отсутствия потерь/дублей.
- Shutdown всего процесса, forced unload и поведение реального loader после
  `NOUNLOAD` не проверялись; соответствующие unit cases имеют более узкую область.
- Существующие ограничения соседних command/logging profiles и нетранзакционного
  reload перечислены в [отчёте этапа 1](producer-lifecycle-stage1.md).

Для расследования повторного падения нужен стек именно остановившегося
процесса с соответствующими ему бинарниками. Менять lifecycle-код на основании
невоспроизведённого SIGSEGV в ходе этой диагностики не потребовалось.
