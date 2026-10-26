# mod_amqp Filter Engine v1.0 — этап 1: исправление жизненного цикла producer-профилей

Дата отчёта: 26 октября 2026 года.

Ветка: `codex/mod-amqp-producer-lifecycle`.
Базовый HEAD: `1ff547f988186de7f1903eba16d5477cde72e27d`.
Изменения находятся в рабочем дереве, без коммита.

Основание: [техническая проверка архитектуры Filter Engine](filter-engine-review.md).
Подробности исполнения в Docker: [отчёт диагностики](docker-segfault-diagnosis.md).

## 1. Результат этапа

Реализовано индивидуальное владение event bindings producer-профилем,
очистка при частичном создании и упорядоченное уничтожение профиля.
Память освобождается после снятия принадлежащих профилю подписок и успешного
ожидания sender. При ошибке unbind/join ресурсы сохраняются для безопасного
последующего teardown.

Чистая сборка модуля в Docker прошла со штатным `-Werror`.
Пройдены **18/18 lifecycle-тестов** и **8 полных reload модуля под GDB**;
три reload выполнялись параллельно с подачей 1284 CUSTOM-событий.
SIGSEGV не зарегистрирован. Прежнее пользовательское падение не воспроизведено,
его первопричина не установлена.

XML Parser, Filter Engine, Matcher и система rules на этом этапе не реализованы.
Исходники FreeSWITCH Core и рабочая конфигурация не изменялись. Изменения
`Makefile.am` ограничены регистрацией тестов модуля; добавлена отдельная
XML-фикстура для тестов. AMQP transport, JSON и routing key сохранены.

## 2. Выполнение требований

| Требование | Реализация и подтверждение |
| --- | --- |
| Producer самостоятельно владеет bindings | Handles хранятся в существующем `event_nodes[]`; destructor обходит все ненулевые slots. Тест независимых профилей подтверждает, что уничтожение одного не снимает подписки другого. |
| Индивидуальный `switch_event_unbind()` | Вызывается для каждого принадлежащего профилю node в `mod_amqp_producer_destroy()`. |
| Отсутствие конфликта с глобальным unbind | `switch_event_unbind_callback(mod_amqp_producer_event_handler)` удалён из штатных reload/shutdown. |
| Очистка частичного создания | Любая ошибка create ведёт в общий destructor; отказ первого, второго и третьего bind проверен с очисткой предыдущих подписок. При ошибке самой очистки профиль сохраняется в hash. |
| Ожидание callback и sender до освобождения | Core unbind служит барьером callback; затем выполняется join sender. Оба ожидания проверены отдельными concurrency-тестами. |
| Защита чужого профиля в hash | Удаление записи выполняется только при равенстве её значения адресу уничтожаемого профиля. Повторное имя при create отклоняется. Оба сценария проверены. |
| Legacy-совместимость `event_filter` | Парсер и кратность подписок сохранены; тесты проверяют ALL, пустое значение, CUSTOM subclass и дубли. Дедупликация не добавлялась. |
| Сохранение транспорта, JSON и routing key | `mod_amqp_producer_send()` и `mod_amqp_producer_routing_key()` не изменены; callback/sender используют прежний путь обработки с новым чтением stop-флага. |
| Потокобезопасный stop-флаг producer | Callback и sender читают `running` под `state_mutex`; destructor пишет под тем же mutex. Начальная запись выполняется до публикации профиля. |

Гарантии lifetime относятся к штатным управляющим путям модуля. Прямые вызовы
create/destroy требуют захваченного `lifecycle_mutex` и запрещены из event
callback; этот контракт указан в
[`mod_amqp.h:229`](../../src/mod/event_handlers/mod_amqp/mod_amqp.h#L229).

## 3. Изменённые файлы и функции

| Файл | Содержание изменения |
| --- | --- |
| [`mod_amqp_producer.c:41`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L41) | Новый `mod_amqp_producer_is_running()`; изменения `mod_amqp_producer_create()`, `mod_amqp_producer_destroy()`; callback и sender читают stop-флаг через accessor. |
| [`mod_amqp.h:134`](../../src/mod/event_handlers/mod_amqp/mod_amqp.h#L134) | `state_mutex` producer, `lifecycle_mutex` и `shutting_down` globals, identity command worker, контракт управления lifecycle. |
| [`mod_amqp_utils.c:91`](../../src/mod/event_handlers/mod_amqp/mod_amqp_utils.c#L91) | Новый `mod_amqp_is_command_thread()`; `mod_amqp_do_config()` сериализует управление, отклоняет опасные reload и прекращает teardown при ошибке producer. |
| [`mod_amqp.c:57`](../../src/mod/event_handlers/mod_amqp/mod_amqp.c#L57) | `mod_amqp_load()` создаёт mutex управления; `mod_amqp_shutdown()` использует индивидуальный teardown и возвращает `NOUNLOAD`, если завершение небезопасно. |
| [`mod_amqp_command.c:100`](../../src/mod/event_handlers/mod_amqp/mod_amqp_command.c#L100) | Инициализация mutex в `mod_amqp_command_create()` и публикация identity в `mod_amqp_command_thread()` для предотвращения self-join. |
| [`Makefile.am:12`](../../src/mod/event_handlers/mod_amqp/Makefile.am#L12) | Регистрация test executable в `check_PROGRAMS`/`TESTS`, его sources, flags и тестовых файлов в `EXTRA_DIST`. |
| [`test/test_producer_lifecycle.c`](../../src/mod/event_handlers/mod_amqp/test/test_producer_lifecycle.c) | Новый набор из 18 тестов с локальной инъекцией отказов. |
| [`test/conf/freeswitch.xml`](../../src/mod/event_handlers/mod_amqp/test/conf/freeswitch.xml) | Новая изолированная фикстура: полный event engine, без динамических модулей, пустой `amqp.conf` для reload-тестов. |
| [`test/README.md`](../../src/mod/event_handlers/mod_amqp/test/README.md) | Команда запуска, устройство тестов и ограничения. |

Сопроводительная документация: настоящий отчёт,
[диагностика Docker](docker-segfault-diagnosis.md) и [передача контекста](HANDOFF.md).
Посторонние локальные изменения проекта в этап не включались.

## 4. Создание и частичные ошибки

В [`mod_amqp_producer_create():201`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L201)
введены следующие правила:

1. Имя проверяется до выделения ресурсов; живой владелец не заменяется.
2. Создаются pool, профиль, mutex состояния, конфигурация и очередь.
3. Профиль вставляется в `producer_hash` до старта sender и регистрации bindings.
   Это оставляет доступ к нему, если последующая аварийная очистка не удастся.
4. Sender создаётся с явно установленным joinable attribute.
5. Успешные bindings записываются в принадлежащие профилю `event_nodes[]`.
6. Ошибка на любом этапе переводит выполнение в общий destructor.

Mutex, очередь и thread handle сначала принимаются в локальные переменные,
а полями профиля становятся только после успешного возврата API. Нельзя
считать ненулевой выходной указатель доказательством успешного create:
например, [`switch_apr_queue_create():88`](../../src/switch_apr_queue.c#L88)
записывает его до завершения инициализации.
Ошибки настройки thread attributes также обрабатываются общим путём очистки.

Если cleanup успешен, частичный профиль удалён из hash и освобождён.
Если unbind/join не удался, create возвращает ошибку, но сохраняет доступный
через hash профиль и логирует отказ очистки. Это намеренное сохранение
ресурсов ради lifetime safety, а не успешная очистка.

## 5. Порядок уничтожения и синхронизация

[`mod_amqp_producer_destroy():125`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L125)
выполняет:

1. Снятие каждого ненулевого binding через `switch_event_unbind()`.
2. Запись `running = SWITCH_FALSE` под `state_mutex`.
3. Ожидание sender через `switch_thread_join()`; handle обнуляется только
   после успешного join.
4. При ошибке unbind/join — возврат ошибки без освобождения profile/pool,
   очереди и соединений. Принадлежащая профилю запись hash сохраняется.
5. При успешных барьерах — удаление hash entry только при совпадении владельца.
6. Закрытие соединений, уничтожение оставшихся сообщений и pool.
7. Обнуление указателя вызывающего кода.

Отказ снятия одного binding не мешает попыткам снять остальные. Даже после
ошибки unbind выполняется остановка и ожидание sender, но профиль сохраняется
для возможных callback. Повторный teardown пропускает уже снятые nodes и
уже joined thread. `destroy(NULL)` и повторный destroy обнулённого указателя
безопасны; это не означает поддержку двух конкурентных destructor одного профиля.

Барьер callback основан на фактической реализации Core:
[`switch_event_deliver():400`](../../src/switch_event.c#L400) удерживает read lock
во время callback, а [`switch_event_unbind():2175`](../../src/switch_event.c#L2175)
захватывает write lock. До завершения unbind профиль и очередь остаются живы.
Сам FreeSWITCH Core не изменялся.

[`mod_amqp_producer_is_running():41`](../../src/mod/event_handlers/mod_amqp/mod_amqp_producer.c#L41)
используется callback и sender. Короткий `state_mutex` защищает только `running`;
он не удерживается во время unbind, join, JSON или AMQP I/O. Mutex выбран
вместо предположений о memory ordering локального APR atomic fallback.

## 6. Необходимые изменения reload и shutdown

Полная переработка reload не выполнялась. Для безопасного владения ресурсами
потребовались следующие изменения существующих управляющих путей:

- `mod_amqp_load()` создаёт нерекурсивный `lifecycle_mutex`.
- `mod_amqp_do_config()` использует trylock и возвращает ошибку при занятом
  mutex, повторном входе или начавшемся shutdown.
- Reload из AMQP command worker отклоняется до teardown: существующий общий
  reload уничтожает и command profiles, поэтому иначе worker мог бы join себя.
- Identity worker публикуется и читается под его mutex. Callback и producer
  sender управляющий mutex не захватывают.
- При ошибке producer teardown reload прекращается; новый профиль не создаётся
  поверх оставшегося владельца.
- Штатные reload/shutdown не вызывают глобальный producer-unbind.
- `mod_amqp_shutdown()` возвращает `SWITCH_STATUS_NOUNLOAD`, если управление
  занято, вызов поступил из command worker или producer teardown не завершён.

Trylock предотвращает также цикл «управляющий поток ждёт command worker,
а worker ждёт mutex reload».

Использование `NOUNLOAD` опирается на
[`do_shutdown():2335`](../../src/switch_loadable_module.c#L2335): запрет выгрузки
DSO проверяется именно по этому статусу, см.
[`switch_loadable_module.c:2365`](../../src/switch_loadable_module.c#L2365).
Обычный `GENERR` такой защиты не даёт.

При этом Core выполняет unprocess interfaces до module shutdown.
`NOUNLOAD` сохраняет DSO/pool, но не гарантирует восстановление API или
успешный повторный CLI unload. Retained resources могут остаться до завершения
процесса. Тест повторяет прямой вызов shutdown, а не восстановление loader.

## 7. Совместимость и границы этапа

Блок разбора `event_filter` сохранён. Повторные и пересекающиеся legacy-подписки
по-прежнему могут вызывать несколько обработок события на профиль.
Универсальная фильтрация и ограничение «не более одной обработки события»
в этом этапе не вводились.

`mod_amqp_producer_routing_key()` и `mod_amqp_producer_send()` сохранены.
В callback и sender изменён только способ чтения `running`;
JSON-сериализация, enqueue/dequeue, reconnect и publish не переписывались.

Намеренные изменения поведения управляющих операций:

- Duplicate producer name отклоняется вместо замены владельца.
- Concurrent/reentrant reload и reload из command worker отклоняются.
- Ошибка producer teardown прекращает reload; небезопасный shutdown запрещает
  выгрузку DSO через `NOUNLOAD`.

Reload остаётся последовательным, без staging, rollback и переноса очередей.
Уже удалённые профили при последующей ошибке не восстанавливаются.
Прежнее логирование ошибок создания отдельных профилей без агрегирования
итогового статуса сохранено.

## 8. Проверки и результаты

### Статические проверки

- `git diff --check` прошёл.
- Сравнение с базовым HEAD подтвердило сохранение parser `event_filter`,
  routing key и AMQP publish; callback/sender изменены только в чтении stop-флага.
- Проверено отсутствие глобального producer-unbind в штатных reload/shutdown.
- Изменения существующих tracked-файлов ограничены каталогом `mod_amqp`.
- Проверены локальные ссылки Markdown и XML-фикстура.

### Lifecycle-тесты: 18/18

Тестовый executable включает production producer с локальными wrappers
для инъекции отказов. Остальные module sources линкуются отдельно.
Event engine, bindings, unbind, queues, pools и join — реальные.
Сетевой sender заменён joinable test worker, читающим production stop accessor.
Hooks в production-код не добавлялись, RabbitMQ для этих тестов не требуется.

| Группа | Проверенные сценарии |
| --- | --- |
| Владение и legacy | Null/repeated destroy; независимые профили; дубли; ALL; пустой фильтр; CUSTOM subclass; duplicate name; чужая hash entry |
| Частичное создание | Отказ первого/второго/третьего bind; mutex/queue/hash/thread creation; недействительные выходные handles ошибочных create API |
| Ошибка очистки | Частичный create с failed unbind/join; сохранение владельца в hash; повторный успешный teardown |
| Конкурентное исполнение | Заблокированный callback внутри сериализации; sender, увидевший stop, но ещё не вышедший; destroy ждёт оба барьера |
| Управление | Concurrent/reentrant reload; command worker reload; 10 последовательных config reload; остановка reload на teardown failure; shutdown и `NOUNLOAD` |

### Docker: сборка и интеграционная проверка

Проверено в контейнере `freeswitch-dev`, образ
`freeswitch-local-dev:mod_speechkit_vscode`; рабочая копия подключена в
`/usr/src/freeswitch`. Свежий Core: `1.10.13-dev git 82bf16a`, rabbitmq-c: `0.11.0`.

| Проверка | Результат |
| --- | --- |
| Чистая пересборка и установка всех шести исходников модуля | Успешно, со штатным `-Werror` |
| `make check` | Успешно |
| Повторная сборка тестов с явной линковкой к свежему установленному Core | 18/18 cases; Automake: 1/1 executable |
| Полные DSO reload через `fs_cli`, процесс под GDB | 8 успешных unload/load, без SIGSEGV |
| Из них reload при потоке CUSTOM-событий | 3 reload; ESL принял 1284 события, ошибок probe нет |
| Завершение диагностики | Core восстановлен, debugger отключён, процесс отвечает, `mod_amqp` загружен |

Приём события ESL не доказывает его публикацию или доставку RabbitMQ;
потери/дубли при этой проверке не измерялись.

Первоначальные попытки сборки в WSL с rabbitmq-c `0.16.0` останавливались
на предупреждениях устаревшего API в существующем коде, затем сборка была
приостановлена пользователем. После разрешения диагностики в Docker
сборка прошла без ослабления compiler flags. Ограничение WSL-сборки
не переносится на результат проверенного контейнера.

## 9. Обнаруженная проблема окружения

`make mod_amqp-install` из корня вызывает также `core_install`:
[`Makefile.am:51`](../../Makefile.am#L51). В volume сохранилась старая
`.libs/libfreeswitch.so.1.0.0` версии `ae5ffee` от 10 января 2025 года,
а свежий образ содержит `82bf16a` от 8 октября 2025 года.
Корневая команда заменяет свежую установленную библиотеку старой;
это подтверждено логом установки и SHA-256.

Свежая библиотека восстановлена. Для установки только модуля в проверенном
окружении использована команда:

```sh
make -C /usr/src/freeswitch/src/mod/event_handlers/mod_amqp -j2 install
```

Она обходит корневой `core_install`, но сама по себе не согласует build-tree,
headers и Core образа. Для воспроизводимой дальнейшей разработки эти версии
нужно выровнять. Исходники Core в рамках этапа не менялись.

Эта проблема **не признана доказанной причиной прежнего SIGSEGV**:
исходного backtrace нет, падение при повторной диагностике не воспроизведено.
Команды, версии, хеши и расположение журналов приведены
в [отчёте диагностики](docker-segfault-diagnosis.md).

## 10. Непроверенные сценарии и оставшиеся риски

1. **Редкие ошибки памяти и гонки.** ASan/UBSan/TSan с инструментированным
   Core и длительный stress не выполнялись; успешные тесты не доказывают
   отсутствие всех use-after-free или deadlock.
2. **Реальный sender и broker.** End-to-end доставка, disconnect/reconnect,
   broker failure, длительное блокирование I/O и реальные звонки не проверены.
   Stop mutex не прерывает синхронное I/O; join может ждать долго.
3. **Loader и shutdown процесса.** Forced unload, завершение всего процесса
   и восстановление loader после `NOUNLOAD` не проверены.
4. **Внешние event callbacks.** Синхронный reload/unbind из callback Core
   опасен из-за read-to-write upgrade общего RWLOCK. Producer callback этого
   не делает; универсальное определение callback-контекста не добавлено.
5. **Command/logging lifecycle.** Добавлена только необходимая identity-защита
   command worker; их stop-флаги, частичные ошибки thread creation и cleanup
   не перерабатывались. Общий config reload всё ещё пересоздаёт эти профили.
6. **Logging reload.** Существующий unbind logger без повторного bind
   в config reload оставлен как отдельная задача.
7. **Соседние гонки и старые риски.** Circuit breaker timestamp между callbacks
   не синхронизирован; прежние риски буфера routing key не исправлялись.
8. **Потери и дубли.** Нет транзакционного reload/rollback, сохранения очередей
   или дедупликации legacy bindings. Окна потерь и множественные вызовы по
   пересекающимся подпискам остаются.
9. **Нарушение владения извне.** Сторонний глобальный unbind оставит сохранённые
   handles недействительными. Исправлены штатные владельцы внутри модуля;
   произвольное вмешательство в Core bindings не поддерживается.
10. **Среда сборки.** В volume остаются артефакты другого Core. Успешные текущие
    проверки не гарантируют совместимость произвольного следующего rebuild
    или запуска с подменённой библиотекой.

## 11. Статус передачи этапа

Реализация producer lifecycle и предусмотренные проверки этапа выполнены.
Изменения не закоммичены. Проверки подтверждают перечисленные сценарии;
production-ready статус и устранение прежнего SIGSEGV этим отчётом не заявляются.

Перед расширением реализации требуется сохранить контракт индивидуального
владения bindings, согласовать окружение сборки и учитывать перечисленные
ограничения reload. Переход к XML Parser, Filter Engine, Matcher и rules
в рамках выполненной работы не начинался.
