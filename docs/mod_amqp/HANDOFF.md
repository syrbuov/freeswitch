# Передача контекста: mod_amqp producer lifecycle

Состояние на 26 октября 2026 года. Этот файл передаёт рабочий контекст
новой сессии Codex; полная история разговора не требуется для продолжения.

## Последние указания пользователя

- FreeSWITCH работает **в Docker-контейнере**; пользователь подключился к нему
  через VS Code. WSL — окружение Docker, а не достаточное описание места
  сборки/исполнения FreeSWITCH. Проверить реальные пути и mounts в контейнере.
- Пользователь позднее разрешил диагностику с пересборкой/установкой и
  reload в контейнере, затем пересоздал контейнер и попросил повторить
  диагностику с нуля. Ранее установленный запрет сборки снят этим поручением.
- В свежем контейнере модуль собран начисто; lifecycle-тесты пройдены 18/18.
  Итоги и ограничения: [диагностика](docker-segfault-diagnosis.md).
- Сейчас выполняется только этап 1 Filter Engine v1.0: producer lifecycle.
  Не начинать XML Parser, Filter Engine, Matcher и систему rules.
- Не менять FreeSWITCH Core, AMQP transport, JSON-сериализацию и routing key.
- Сохранить legacy-поведение `event_filter`, включая пересекающиеся подписки.

## Ветка и рабочая копия

- Ветка: `codex/mod-amqp-producer-lifecycle`.
- Базовый HEAD: `1ff547f988186de7f1903eba16d5477cde72e27d`.
- Изменения **не закоммичены**. Одного checkout ветки в другой копии репозитория
  недостаточно для переноса patch и новых файлов.
- Путь рабочей копии предыдущей сессии:
  `/root/freeswitch-devcontainer/freeswitch-develop`.
- В generated Makefiles встречается `/usr/src/freeswitch`; не считать эти
  каталоги одной рабочей копией без проверки.
- В дереве изначально было много посторонних untracked-файлов; их не удалять
  и не включать автоматически в текущие изменения.

Для первичной проверки достаточно read-only команд `pwd`,
`git branch --show-current`, `git status --short` и `git diff`.
Не выполнять Git reset/clean и не удалять посторонние локальные изменения.
Для дальнейших действий учитывать актуальное поручение пользователя.

## Что прочитать

1. [Архитектурная проверка](filter-engine-review.md).
2. [Отчёт по подготовленным изменениям этапа 1](producer-lifecycle-stage1.md).
3. [Первоначальный анализ mod_amqp](../../src/mod/event_handlers/mod_amqp/mod_amqp-technical-report.md).
4. [Описание тестов](../../src/mod/event_handlers/mod_amqp/test/README.md).
5. [Повторная диагностика свежего Docker-контейнера](docker-segfault-diagnosis.md).
6. Текущий `git diff`: изменения остаются незакоммиченными; тесты и обычный
   reload проверены, sanitizers и ряд аварийных сценариев ещё не проверены.

## Подготовленные изменения

- Producer destructor индивидуально снимает каждый ненулевой `event_nodes[]`
  через `switch_event_unbind()`, ожидает завершения callback, останавливает и
  join sender, затем освобождает очередь, соединения и pool.
- При failed unbind/join профиль и его ресурсы сохраняются, ошибку можно
  обработать без освобождения памяти живого callback/thread.
- Hash entry удаляется только при совпадении указателя владельца. Duplicate
  producer names отклоняются. Профиль публикуется в hash до старта sender и
  bindings, чтобы оставаться отслеживаемым при отказе аварийной очистки.
- Handles mutex/queue/thread становятся полями профиля только после успешного
  возврата create API; частично заполненный выходной handle не используется.
- Stop-флаг producer защищён коротким `state_mutex`. Callback и sender читают
  его через `mod_amqp_producer_is_running()`; destructor пишет под тем же mutex.
  Mutex не удерживается во время unbind/join/I/O.
- Глобальный producer-unbind убран из reload/shutdown. Добавлен нерекурсивный
  управляющий `lifecycle_mutex` с trylock и остановка reload на teardown error.
- Command worker публикует thread identity под своим mutex, чтобы попытка
  reload из этого worker отклонялась до self-join. AMQP command transport
  при этом не менялся.
- Shutdown при невозможности безопасного завершения возвращает `NOUNLOAD`.
  Это сохраняет DSO/pool, но не гарантирует восстановление interfaces loader.

Изменены существующие файлы только в `src/mod/event_handlers/mod_amqp/`:
`mod_amqp.h`, `mod_amqp_producer.c`, `mod_amqp.c`, `mod_amqp_utils.c`,
`mod_amqp_command.c`, `Makefile.am`.
Добавлены `test/test_producer_lifecycle.c`, `test/conf/freeswitch.xml`,
`test/README.md` и отчёт по этапу 1.

## Проверки и оставшиеся ограничения

- Статически проверено: парсер `event_filter`, routing key и AMQP publish
  побайтово сохранены; callback и sender отличаются только чтением stop-флага.
  `git diff --check`, ссылки отчётов и XML test fixture прошли проверку.
- Подготовлены **18 lifecycle-тестов** на `switch_test.h`, реальном event engine,
  bindings, очередях, pools и join. Fault injection локален тестовому executable;
  сетевой sender заменён joinable test worker. В Docker пройдены все 18 тестов.
- До запрета выполнялись две попытки сборки только модуля. Их остановили
  deprecated compatibility headers и `amqp_set_initialize_ssl_library()`
  установленного `rabbitmq-c 0.16.0` при `-Werror`. Это не проверка финальной
  версии: после попыток код дорабатывался. В Docker с rabbitmq-c 0.11.0
  чистая сборка прошла со штатными compiler flags.
- Лог прежней попытки `/tmp/mod-amqp-lifecycle-build.log` может быть недоступен
  в другом контейнере. Промежуточные `.lo` не являются готовым проверенным модулем.
- Остались прежние риски: нет транзакционного reload/rollback, теряется остаток
  очередей, join может долго ждать I/O, circuit breaker timestamp не синхронизирован,
  соседний logging reload не переподключает logger. Полный command/logging
  lifecycle и произвольный вызов reload из внешнего event callback не исправлены.
- ASan/UBSan/TSan и достоверность доставки в реальный RabbitMQ не проверялись.
  Восемь полных DSO reload проверены под GDB, включая три при потоке событий.
- В свежем контейнере segfault не воспроизведён. `make mod_amqp-install` из
  корня также выполняет `core_install` и заменяет свежую библиотеку Core
  старой из volume `.libs`. Это подтверждено хешами и логом установки.
  Свежая `.so` восстановлена, `.la` совпадает с образом, GDB отключён.
- Фактический контейнер: `freeswitch-dev`, образ
  `freeswitch-local-dev:mod_speechkit_vscode`; проект смонтирован в
  `/usr/src/freeswitch`. Для установки только модуля проверена команда
  `make -C /usr/src/freeswitch/src/mod/event_handlers/mod_amqp install`.
  Она не устраняет общего несоответствия артефактов сборки и образа Core.

## Первый шаг новой сессии

Прочитать этот файл и отчёты, проверить ветку, наличие незакоммиченного diff
и новых файлов именно в контейнере. Учитывать уже выполненные проверки
и подтверждённое смешение Core, не повторять их без новой причины.
Не считать прежний segfault объяснённым: backtrace исходного падения нет.
