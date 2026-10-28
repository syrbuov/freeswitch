# mod_amqp: диагностика профилей и восстановление TCP

Дата: 28 октября 2026 года. Основание — пользователь отложил DNS/TLS и
продолжил доработку producer/logging без изменений Core. Command-профили
остаются отключёнными. Этот этап включает текущую реализацию
[lifecycle без Core](filter-engine-lifecycle-without-core.md) и следующие изменения.
DNS resolver, TLS-приёмка, работающий сервис и установленный модуль не менялись.

## API

- `amqp` и `amqp reload` выполняют конфигурационный reload.
- `amqp status` сохраняет краткий ответ ACTIVE/DEGRADED/RESTART_REQUIRED и
  работает без ожидания lifecycle mutex. ACTIVE относится к конфигурации.
- `amqp profiles` возвращает `+OK mod_amqp profiles`, затем JSON с массивами
  `producers`, `logging` и `commands: "disabled"`. Снимок не выполняет I/O.
  Если lifecycle занят, ответ — `-ERR mod_amqp profile snapshot busy`.
- Неизвестный аргумент возвращает usage error и не выполняет reload.

Для каждого профиля возвращаются:

| Поле | Значение |
| --- | --- |
| name | Имя XML-профиля, экранируется JSON serializer |
| enabled | Текущее запрошенное running, false после stop |
| worker_running | Worker вошёл в production loop и ещё не начал финальный выход |
| join_pending | Созданный thread handle ещё не присоединён; не равнозначно worker_running |
| connection | Последнее наблюдённое состояние: disconnected, connecting, ready, stopped |
| last_error | Историческая фаза последнего отказа, без endpoint/credentials; сохраняется после восстановления |
| queue_depth / queue_capacity | Текущее число queued messages и настроенная вместимость |
| connect_attempts / connect_failures | Попытки подключений и отказы подключения/подготовки канала/exchange |
| publish_ok / publish_errors | Успешный локальный возврат publish и ошибки publish; не broker confirms |
| enqueued / dropped / filtered | Поставленные в очередь, явно отброшенные и отклонённые rules события/копии |
| retained | Для producer: management оставил владельца после ошибки очистки |

Счётчики — десятичные **строки uint64** для сохранения точности JSON-клиентами.
Они принадлежат поколению профиля и обнуляются при его пересоздании. Это
не постоянная статистика с момента запуска процесса. `dropped` учитывает
ошибку routing/JSON/enqueue, circuit breaker и явно уничтоженные pending
сообщения; не измеряет потери в сети или на стороне RabbitMQ.

Состояние ready устанавливается после успешного exchange.declare. Оно не
является активным health probe и может устареть при тихом разрыве соединения.
Глубина очереди и worker counters читаются последовательно, а не как одна
транзакция с AMQP publish.

Lifecycle mutex защищает владельцев профилей; profile mutex — worker fields
и counters. JSON копирует имена/данные до освобождения lifecycle mutex;
формирование ответа не обращается к освобождаемым profile pointers.
Ожидание пользователя/stream writer выполняется после снятия lifecycle lock.

## Исправления ревью

1. Logging получает reconnect_interval_ms=1000 по умолчанию вместо нуля.
2. При ошибке exchange.declare оба sender закрывают неготовое соединение,
   обнуляют active pointer и выдерживают reconnect interval. Они не переходят
   к публикации на неготовом канале.
3. Ошибка publish также включает прерываемую reconnect-задержку. Stop будит
   её через существующую condition variable.
4. Client property keys AMQP login имеют пять независимых буферов. Ранее все
   указывали на одну перезаписываемую строку. Обработаны NULL custom_attr и
   отсутствие завершающего NUL у предельно длинного системного hostname.
5. MOD_AMQP_DEBUG_TIMING=0 теперь действительно отключает timing block
   через #if: прежний #ifdef включал общий static counter между producers.
6. Publish logs передают отрицательный код в amqp_error_string2 напрямую;
   прежнее изменение знака давало `(unknown error)` вместо причины.

## Проверки

Базовая регрессия: engine 19/19, lifecycle 18/18, integration 45/45. Новые ESL
cases проверяют read-only snapshot, занятый lifecycle, доступность status,
retained owner и точность UINT64_MAX; неизвестная команда не переключает набор.
Integration ASan/UBSan/LSan и TSan прошли 45/45. Сборка выполняется с -Werror.

Real-DSO runner расширен до 10 TCP-сценариев, все прошли обычный запуск,
ASan/UBSan/LSan и TSan. Каждый реальный профиль проверяется через amqp profiles:
worker_running=true и ожидаемая фаза соединения. Заглушка проверяет пять
различных custom client property keys (стандартные свойства библиотеки
допускаются). Новый declare-recovery намеренно отказывает первому declare
каждого профиля; затем оба восстанавливаются. Проверены две connect attempts,
один failure, ready и сохранённый last_error=exchange_declare. Повторное
подключение происходит с задержкой, а не в интенсивном цикле. Logging в этом
сценарии использует именно default delay без XML override.

В конце каждого probe совпадают workers/joined и bindings/removed;
early_pool_free=0. В сценариях publish перед stop подтверждён незавершённый
реальный amqp_basic_publish. Core/APR/rabbitmq-c остаются неинструментированными.

Полные журналы находятся в контейнере в `/tmp/mod-amqp-profiles-final-*`.
Компактная сводка: [profile-diagnostics-results.txt](profile-diagnostics-results.txt).
Только после полного прогона исправлен знак кода в тексте publish log;
для этого отдельно проверены значения amqp_error_string2 установленной
библиотеки, затем повторены сборка/регрессия. Проверки не отключались.

## Оставшаяся работа

DNS/TLS **отложены пользователем**, не объявлены исправленными/проверенными.
Следующий этап — реальный RabbitMQ по числовому IP/TCP, интеграция с приложением
без AMQP commands, затем длительная нагрузочная приёмка и canary/откат.
Publisher confirms, постоянная очередь и гарантия доставки не реализованы.
Сохраняются ограничения Core после аварийного cleanup и управления из
callback, перечисленные в основном lifecycle-отчёте. Production-готовность
этим этапом не объявляется; установка и push не выполнялись.
