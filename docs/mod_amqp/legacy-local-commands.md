# mod_amqp: отдельная ветка с прежними commands для локальных тестов

Дата: 28 октября 2026 года. По указанию пользователя текущая работа разделена:

| Ветка | Содержимое |
| --- | --- |
| codex/mod-amqp-commands-esl | ESL executor, тесты и отчёты сохранены коммитом cf7a441125 |
| codex/mod-amqp-commands-local-test | Непосредственно от 6bf07b9ba2; прежние command-профили включены для локального тестового приложения |
| codex/mod-amqp-filter-engine-stage3 | Осталась на базовом коммите 6bf07b9ba2 |

Этот отчёт относится к **local-test**. ESL-коммит не является её предком.
Ветка не содержит ESL executor, его новых настроек, allow-list или формата
command diagnostics. Рабочие сервисы, установленный модуль и XML не менялись;
push не выполнялся. Stash и посторонние файлы сохранены.

## Что изменено относительно базы

- mod_amqp_do_config снова создаёт `<commands><profile .../></commands>` через
  mod_amqp_command_create, проверяя пустые/повторные имена и результат создания.
  Ошибки соседних профилей доходят до reload API, как прежде.
- Существующий mod_amqp_command.c не изменён: прямой switch_console_execute
  на command worker, старый разбор сообщений и прежний optional AMQP response.
  Пустые response headers не нужны: для режима без ответа **не передавать**
  x-fs-api-resp-exchange/x-fs-api-resp-key. Сам механизм ответов сохранён,
  но отдельной новой сетевой приёмки RPC на этом этапе не проводилось.
- Status и profiles показывают commands=legacy-local-test / строку
  commands:"legacy-local-test". Это режим кода, а не свидетельство существования
  активного command worker; расширенные command snapshots из ESL-ветки отсутствуют.
- Тесты снова проверяют создание command-профилей из legacy XML, failed create,
  сохранение owner при failed join и успешный retry cleanup. Проверяется
  отсутствие профилей после reload пустого `<commands/>`.

Producer/logging, filter engine, connection implementation и layout mod_amqp.h
идентичны базе 6bf07b9ba2. Исправления их lifecycle сохранены. Core и libs/esl
не менялись, DNS/TLS остаются отложенными.

## Использование

Локальная конфигурация: [legacy-local-command-example.xml](legacy-local-command-example.xml).
ESL listener/пароль, executor=esl и response-mode для этой ветки не нужны.
Команды поступают через RabbitMQ. Старый executor принимает plaintext body
с именем команды FreeSWITCH, например:

```text
uuid_kill <call-uuid>
uuid_setvar <call-uuid> variable value
bgapi originate <dial-string> &park()
```

Префикс `api ` в этих примерах не является частью AMQP body: это прежний console
контракт, не синтаксис ESL API request. Для используемого режима без ответа
приложение не должно добавлять legacy response headers. Установление соединения
с RabbitMQ и успешная публикация не доказывают выполнение команды FreeSWITCH.

В production command-профили должны отсутствовать:

```xml
<commands/>
```

Можно также убрать раздел commands полностью. Сам код не проверяет, что
отправитель локальный: ограничение отправителей задаётся конфигурацией доступа
к брокеру. Стандартный vanilla amqp.conf.xml содержит command profile;
его нельзя переносить в production без удаления этого профиля. Рабочий
production XML в рамках этого изменения не редактировался.

## Сохранившиеся ограничения legacy executor

Это возврат старого поведения для доверенного локального приложения.
Произвольный console API выполняется на стеке mod_amqp. Reload/unload/shutdown,
их aliases и косвенное управление модулем из команды не поддерживаются.
Долгий API задерживает join, а self-unload способен повредить registry или
привести к deadlock. Локальный источник команд сам по себе этого не исправляет.

У command worker остались прежние reconnect sleep, consume/frame и synchronous
execution; на него не переносятся доказанные пределы остановки producer/logging
или ESL executor. RPC headers/body parser также остаётся прежним. AMQP no_ack
допускает потери; publisher confirms, идемпотентность и exactly-once не добавлены.
Расширенные гарантии безопасного command ingress находятся только в отдельной
ESL-ветке и не заявляются для local-test.

## Проверки

Сводка: [legacy-local-commands-results.txt](legacy-local-commands-results.txt).
Сборка -Wall -Werror и make check: engine 19/19, lifecycle 18/18,
integration 46/46. Integration проверяет реальный event engine/ESL API replies,
но заменяет network workers на контролируемые test workers; это не зависимость
локального executor от ESL.

Integration ASan/UBSan/LSan и TSan прошли 46/46. Два legacy real-DSO сценария
прошли normal и ASan/UBSan/LSan, каждый exit 0. Producer/logging с пустым
commands повторно прошли 10/10 normal network probes.

Real-DSO runner дополнен `--legacy-commands`: изолированный Core загружает
production mod_amqp и установленный mod_commands; loopback AMQP stub выдаёт
uuid_exists для отсутствующего канала и bgapi originate для недоступного
error endpoint, без внешнего звонка. Test-only interposer передаёт вызовы
реальному console executor и фиксирует два завершённых вызова, вывод false и
квитанцию Job-UUID. Профиль создан без каких-либо ESL-настроек.

Проверяются unload после обработки команд и shutdown процесса с таким профилем:
workers=joined=1, early_pool_free=0. Это не проверка остановки во время
произвольного API/неотвечающего command broker. Producer/logging probes используют
пустой `<commands/>` и по-прежнему проверяют два своих worker.

**Real-DSO TSan не прошёл:** оба legacy сценария завершились exit 66 при
завершении всего Core. Стек указывает на pthread_rwlock_destroy при очистке
APR pool и предыдущий pthread_rwlock_unlock в mod_commands bgapi_exec.
Отдельный `--core-bgapi --sanitizer thread` воспроизводит тот же отчёт **без
загрузки mod_amqp**, connections=0, exit 66. Изоляция показывает, что этот
TSan-отчёт не требует command worker mod_amqp; окончательная локализация
поведения Core/APR/неинструментированных DSO остаётся за рамками этой ветки.
Проверка не подавлялась и не засчитывается как PASS, Core не исправлялся.

```sh
python3 test/run_lifecycle_probes.py /tmp/legacy-normal --legacy-commands
python3 test/run_lifecycle_probes.py /tmp/legacy-asan --legacy-commands --sanitizer address,undefined
python3 test/run_lifecycle_probes.py /tmp/legacy-tsan --legacy-commands --sanitizer thread
# В текущей среде ожидается exit 1 runner / exit 66 дочернего Core-only процесса:
python3 test/run_lifecycle_probes.py /tmp/core-bgapi-tsan --core-bgapi --sanitizer thread
```

Санитайзеры инструментируют module/harness/interposer, не установленный Core,
APR, mod_commands и rabbitmq-c. PASS не является production-приёмкой command
executor или проверкой всех сценариев реального приложения/RabbitMQ.
