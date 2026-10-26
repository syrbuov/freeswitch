# mod_amqp Filter Engine v1.0 — этап 2: независимый Parser / Compiler / Matcher

Дата: 26 октября 2026 года.
Ветка: `codex/mod-amqp-filter-engine-stage2`.
Baseline: `f6c581830a6e7c212b63b9e4ee9261ee7b187f8f` — завершённый этап producer lifecycle.
Изменения этапа 2 подготовлены в рабочем дереве, без коммита.

Основания: [проверка архитектуры](filter-engine-review.md) и
[результаты этапа 1](producer-lifecycle-stage1.md).

## 1. Результат и границы

Реализован отдельно тестируемый whitelist engine. Parser проверяет standalone
XML и создаёт DTO; Compiler повторно проверяет DTO, создаёт независимый
immutable engine, event index и план subscriptions; Matcher возвращает одно
булево решение без аллокаций и изменения входных данных.

Подготовка не создаёт bindings, очереди, соединения или потоки и не обращается
к active hash. Код producer lifecycle, callback, reload, transport, JSON,
routing key, command/logging profiles и FreeSWITCH Core не изменён.
Runtime mode switch действующего producer не добавлен. Legacy остаётся
прежним; новая функциональность доступна только через standalone API.

Модуль собран со штатным `-Werror`. Пройдены **19/19 тестов engine** и
**18/18 lifecycle-тестов**. ASan/UBSan с LSan и TSan прошли 19/19 тестов
при минимальной инициализации Core. Полные Core sanitizer-прогоны имеют
отдельные ограничения, перечисленные ниже.

Новый модуль не устанавливался и не загружался в работающий FreeSWITCH;
root install и reload не выполнялись.

## 2. Baseline и сохранённые локальные изменения

Перед началом подтверждено наличие коммита этапа 1 и отсутствие tracked
изменений. Создана отдельная ветка от `f6c581830a`.
`AGENTS.md` в проверенном дереве проекта не найден. Согласованной XML-грамматики
rules в предыдущих документах или коде не было.

В исходном рабочем дереве оставались следующие посторонние untracked пути;
они не удалялись, не перезаписывались и в реализацию этапа не включены:

```text
.vscode/tasks.json
build/.cmake/
build/CMakeCache.txt
build/CMakeFiles/
build/build.ninja
build/cmake_install.cmake
build/compile_commands.json
src/mod/applications/mod_example/
src/mod/asr_tts/mod_unimrcp/
src/mod/asr_tts/mod_vosk/
src/mod/codecs/mod_amr/test/test_amr
src/mod/endpoints/mod_wsbridge/
src/mod/event_handlers/mod_amqp/test/adoption-token.dat
src/mod/event_handlers/mod_amqp/test/test_producer_lifecycle
src/mod/event_handlers/mod_event_grpc/
tests/unit/switch_core_asr
tests/unit/switch_sip
tests/unit/test_tts_format
```

Generated Makefiles и тестовые бинарники обновлялись только как артефакты
необходимых проверок. Исходники lifecycle-тестов этапа 1 не менялись.

## 3. Состав реализации

| Файл | Назначение |
| --- | --- |
| [`mod_amqp_filter.h`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter.h) | Публичный standalone API, opaque DTO/engine, лимиты, статусы и структурированная ошибка |
| [`mod_amqp_filter_internal.h`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_internal.h) | Внутреннее представление DTO, compiled rules, buckets; проверка размеров и ASCII case folding |
| [`mod_amqp_filter_parser.c`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_parser.c) | Строгая проверка XML, канонических имён событий, лимитов; создание и очистка DTO |
| [`mod_amqp_filter_compiler.c`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_compiler.c) | Повторная валидация DTO, копирование строк, index, subscription plan, очистка engine |
| [`mod_amqp_filter_matcher.c`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_matcher.c) | Read-only OR/AND matching конкретного и общего buckets |
| [`test/test_filter_engine.c`](../../src/mod/event_handlers/mod_amqp/test/test_filter_engine.c) | 19 тестов на FST, реальных XML/events/headers, инъекция ошибок и проверка аллокаций |
| [`test/run_filter_engine_sanitizers.sh`](../../src/mod/event_handlers/mod_amqp/test/run_filter_engine_sanitizers.sh) | Изолированная сборка и запуск ASan/UBSan/LSan и TSan без установки |
| [`Makefile.am`](../../src/mod/event_handlers/mod_amqp/Makefile.am) | Сборка трёх engine sources в модуле, новый `check_PROGRAMS`, distribution файлов |
| [`test/README.md`](../../src/mod/event_handlers/mod_amqp/test/README.md) | Команды обычных и sanitizer-проверок, устройство тестов |
| `docs/mod_amqp/filter-engine-stage2.md` | Настоящий отчёт |

## 4. Грамматика и семантика

```xml
<filter mode="rules">
  <rule>
    <event name="CUSTOM"/>
    <condition field="Event-Subclass" op="eq" value="sofia::register"/>
    <condition field="variable_tenant" op="eq" value="acme"/>
  </rule>
</filter>
```

- Корень — `filter`, обязательный точный `mode="rules"`.
- Дочерние `rule` объединяются через OR.
- Внутри `rule` несколько `event` образуют OR-набор event IDs.
- Отсутствие `event` означает любой тип; пустое правило без selectors и
  условий запрещено. Явный ALL без условий разрешает все валидные типы.
- Условия внутри правила объединяются через AND. Правило успешно, если
  выполнен selector и все его условия.
- Ноль правил — корректный deny all, ноль subscriptions.
- Поддерживается только точный оператор `eq`; `value` обязателен, `value=""`
  разрешён. Regex, отрицания, deny rules и выражения отсутствуют.
- Неизвестные/повторные атрибуты, неизвестные элементы, вложения в leaf nodes,
  неподдерживаемые операторы/режимы и непробельный текст отклоняются.
  Требуемые атрибуты должны присутствовать явно: DTD defaults их не подставляют.
- Имена XML-элементов, атрибутов и значения mode/op регистрозависимы.

По уточнению пользователя принимаются **оба точных написания** события:
`CUSTOM` и `SWITCH_EVENT_CUSTOM`, аналогично для всех enum values, включая
`ALL` / `SWITCH_EVENT_ALL`. Нижний регистр, сокращения, пробелы и произвольные
префиксы отклоняются. Реализация сопоставляет имена с `switch_event_name()`;
нестрогий `switch_name_event()` не используется.

Event selector обращается только к `event->event_id`. Поле `Event-Subclass`
обращается только к `event->subclass_name`. Одноимённые headers не могут
подменить эти внутренние значения. `Event-Name` в condition отклоняется с
указанием использовать `event`; `_body` явно запрещён.

Имена полей сравниваются без учёта ASCII-регистра, независимо от locale.
Значения сравниваются побайтово с учётом регистра после XML-декодирования.
Отсутствующее значение не равно пустой строке; `NULL` subclass не соответствует
`value=""`, а существующий пустой subclass соответствует.

Для обычного header действует ANY по всем логическим значениям всех
одноимённых узлов. Scalar использует `value`, массив — элементы `array`
с индексами `[0, idx)`, повторяющиеся узлы обходятся полностью. Два AND-условия
одного имени могут совпасть на разных элементах или узлах.

Строка `ARRAY::…` у массива не используется как логическое значение.
Проверка с реальным Core дополнительно показала, что после обновления
существующего array index эта строка может оставаться устаревшей.
Тест проверяет игнорирование фактического кеша и чтение актуальных элементов.

## 5. API, ошибки и владение памятью

Объявления: [`mod_amqp_filter.h:47`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter.h#L47).

| API | Контракт |
| --- | --- |
| `mod_amqp_filter_parse(xml, &dto, &error)` | Проверяет XML и создаёт самостоятельный DTO; XML остаётся у вызывающего кода |
| `mod_amqp_filter_dto_destroy(&dto)` | Освобождает весь DTO и обнуляет handle; NULL/repeated destroy допустимы |
| `mod_amqp_filter_compile(dto, &engine, &error)` | Проверяет DTO и создаёт независимый engine со всеми нужными строками |
| `mod_amqp_filter_engine_destroy(&engine)` | Освобождает engine после завершения читателей; обнуляет handle |
| `mod_amqp_filter_subscriptions(engine, &count)` | Возвращает borrowed const plan; пустой/NULL engine даёт NULL и count=0; count может быть NULL |
| `mod_amqp_filter_match(engine, event)` | Возвращает `SWITCH_TRUE` или `SWITCH_FALSE`; NULL-аргументы и неверные event IDs безопасно отклоняются |

Output slot parse/compile должен быть пустым и не содержать живой объект.
При ошибке `*out == NULL`; частичный результат очищается внутри функции.
Error pointer может быть NULL. Статусы: `OK`, `INVALID`, `LIMIT`, `NO_MEMORY`.
Ошибка содержит код, позиции rule/selector/condition (с 1; 0 означает
неприменимость) и фиксированный буфер причины. XML line numbers не выдумываются.

Parser сначала валидирует весь переданный XML subtree, затем выделяет DTO.
При разборе требуется уже инициализированный Core event subsystem для таблицы
имён; сам parser его не запускает. Исходный XML должен оставаться стабильным
во время parse. После успешного parse XML можно уничтожить до compile.

DTO и engine используют освобождаемые heap allocations, не active pool.
Compiler копирует строки повторно; DTO можно уничтожить сразу после compile.
Subscription plan принадлежит engine и не переживает его destroy.
Публичные типы opaque; Matcher принимает const engine/event и не сохраняет
указатели на событие после возврата.

Тесты включают production sources с локальной подменой malloc/calloc/free:
проверяется отказ каждой аллокации типичного двухправильного DTO/engine и
нулевой баланс после очистки. Hooks в production sources не добавлены.
Core XML allocations, выполняемые до входа в Parser, этим fault injection
не охватываются.

## 6. Лимиты и event index

| Ограничение | Значение |
| --- | --- |
| Правила | 1024 |
| Условия на правило | 32 |
| Значение condition | 4096 байт, без завершающего NUL |
| Имя поля | 255 байт, без завершающего NUL; пустое запрещено |
| Сумма скопированных field/value strings | 4 MiB на DTO и отдельно 4 MiB на engine, с завершающими NUL |

Selector names разрешаются в IDs и не копируются. Повторные selectors занимают
один slot массива выбранных IDs; отдельного растущего массива строк selectors нет.
Лимит strings относится к собственным копиям engine/DTO, а не к исходному XML,
диагностике или структурам. В период compile одновременно могут жить обе
копии строк, исходный XML и служебные allocations.

Проверяются сложение string sizes и умножение размеров allocations на
`SIZE_MAX`. Все лимиты проверены на границе и при превышении на единицу.
Для суммарного бюджета тест использует ровно 4 MiB, затем 4 MiB + 1 байт.
Compiler повторно проверяет лимиты и корректность нормализованного DTO.

В [`mod_amqp_filter_internal.h:40`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_internal.h#L40)
engine содержит `SWITCH_EVENT_ALL + 1` buckets. Конкретные правила размещаются
только в своих buckets; общие — только в ALL. Дубли selectors нормализуются,
ALL вместе с конкретными selectors становится одним общим selector.
Index references хранятся в одном принадлежащем engine массиве.

План формируется в
[`mod_amqp_filter_compile():73`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_compiler.c#L73):
есть общие правила — ровно один ALL; иначе — уникальные конкретные IDs
в enum-порядке. Subclass у каждой subscription равен ANY/NULL.
Регистрация не выполняется. Тест проверяет покрытие планом каждого
совпавшего event ID на всём enum, включая CUSTOM=0 и ALL.

[`mod_amqp_filter_match():39`](../../src/mod/event_handlers/mod_amqp/mod_amqp_filter_matcher.c#L39)
проверяет конкретный bucket, затем общий с short-circuit. При event_id=ALL
общий bucket проверяется один раз. После первого совпавшего правила
возвращается true; количество совпадений не порождает дополнительные действия.

Matcher не использует lifecycle mutex, изменяемые глобальные данные, JSON,
enqueue, AMQP или event management. Object-файл штатной сборки содержит
единственную внешнюю зависимость `strcmp`; malloc/calloc accounting
подтверждает отсутствие собственных аллокаций при match.
Владелец обеспечивает стабильность события и жизнь engine до завершения всех
читателей. Конкурентный destroy или изменение event не поддерживается.

## 7. Проверенная среда и команды

Контейнер: `freeswitch-dev`, образ `freeswitch-local-dev:mod_speechkit_vscode`.
Volume проекта: `/usr/src/freeswitch`. GCC, Automake, rabbitmq-c `0.11.0`.

Существующее несоответствие build artifacts сохранено и учтено:

- Загруженный/установленный Core: `82bf16a`, 8 октября 2025 года.
- `.libs/libfreeswitch.so.1.0.0` из volume: `ae5ffee`, 10 января 2025 года.
- Generated version header содержит revision baseline `1ff547f`.
- `switch_event.h`, `switch_types.h`, `switch_xml.h` побайтово совпали
  с установленными headers. Соответствующие Core event/XML sources и headers
  не отличаются от commit `82bf16a286`.
- Тестовые binaries явно связаны с `/usr/local/freeswitch/lib/libfreeswitch.so`;
  разрешение runtime-библиотеки подтверждено `ldd` внутри контейнера.

Модуль по-прежнему линкуется через прежний build-tree `.la`; его установка
или новая runtime ABI-совместимость не заявляются. Core не пересобирался.
Root install не использовался, установленный Core сохранил SHA-256:
`85774d8dc221b300d12e342ccacf76ce397946bf2044d77cb7f2d232a72a2145`.

Generated module Makefile подготовлен из `Makefile.am`:

```sh
cd /usr/src/freeswitch
automake --foreign src/mod/event_handlers/mod_amqp/Makefile
./config.status src/mod/event_handlers/mod_amqp/Makefile
```

Штатная сборка и оба test executables:

```sh
cd /usr/src/freeswitch/src/mod/event_handlers/mod_amqp
make -j2 mod_amqp.la check \
  test_test_filter_engine_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so" \
  test_test_filter_engine_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib" \
  test_test_producer_lifecycle_LDADD="/usr/local/freeswitch/lib/libfreeswitch.so -lrabbitmq" \
  test_test_producer_lifecycle_LDFLAGS="-no-undefined -Wl,-rpath,/usr/local/freeswitch/lib"
```

Изолированная sanitizer-сборка теста из тех же production sources:

```sh
sh test/run_filter_engine_sanitizers.sh /tmp/mod-amqp-stage2/final-sanitizers /usr/local/freeswitch/lib
```

Helper использует C99, `-Wall -Werror`, `-O1 -g -fno-omit-frame-pointer`,
`-fsanitize=address,undefined` или `-fsanitize=thread`, явную установленную
libfreeswitch и `timeout 90s`. ASan запускается с `detect_leaks=1:halt_on_error=1`,
UBSan/TSan — с `halt_on_error=1`; suppressions не используются.
Тестовая переменная `MOD_AMQP_FILTER_TEST_MINIMAL=1` выбирает SCF_MINIMAL,
сохраняя все 19 cases, реальные events/headers и читательские потоки.
Обычный `make check` использует полную инициализацию Core.

## 8. Результаты проверок

| Проверка | Фактический результат |
| --- | --- |
| Штатная сборка трёх engine sources и модуля, `-Werror` | Успешно |
| FST engine, полный Core | 19/19, финальный прогон 0.231122 s |
| FST lifecycle этапа 1, полный Core | 18/18, финальный прогон 0.071489 s |
| Automake | 2 test executables, PASS=2, FAIL=0 |
| ASan/UBSan + LSan, minimal Core | 19/19, exit 0; без ошибок и утечек, 0.472592 s |
| TSan, minimal Core | 19/19, exit 0; без сообщений о гонках, 1.992762 s |
| Параллельное чтение | 8 отдельных events, 8 readers × 20 000 match calls, без ошибок |
| Matcher allocations | 0; дополнительно штатный object импортирует только `strcmp` |
| Сохранение production paths | Diff существующего C-кода относительно baseline пуст |
| Установленный Core и активный модуль | Хеш Core прежний; `module_exists mod_amqp` = true; установка/reload не выполнялись |

Тестами покрыты строгая грамматика и позиции ошибок, все event IDs и оба
точных написания имён, OR/AND, несколько совпадающих правил, ноль правил,
ALL, неверные IDs, нормализация, уникальность/покрытие subscriptions,
канонические поля против headers, регистр, отсутствующие/пустые значения,
scalar/PUSH/UNSHIFT/indexed arrays, repeated headers, независимые ANY-условия,
жизнь после удаления XML/DTO, неизменность event/engine, лимиты,
переполнение размеров, ошибки каждой текущей malloc/calloc типового DTO/engine,
и отсутствие управленческих side effects.

Дополнительные полные Core sanitizer-прогоны **не считаются успешными**:

- ASan/UBSan выполнил 19/19 engine tests, но процесс завершился с exit 1
  из-за LSan: 344355 байт / 532 allocations, стеки Core hashtable, SQLite
  и сторонних библиотек. Счётчик собственных engine allocations был нулевым.
- TSan с полной инициализацией остановился с exit 66 на
  `destroy of a locked mutex` в `libks2`, `ks_rwl_cleanup`; прогон не завершился успешно.
- После выбора minimal Core оба sanitizer-прогона прошли без suppressions.
  Это проверка инструментированных engine/test sources; установленный Core
  и остальные DSO не пересобирались с sanitizers. Полное покрытие внутренних
  обращений Core и его lifecycle этой проверкой не обеспечено.

Журналы в контейнере: `/tmp/mod-amqp-stage2/final-check.log`,
`final-sanitizers/*.build.log`, `final-sanitizers/*.log`;
неуспешные полные прогоны — `asan.log`, `tsan.log`.
FST журналы штатного запуска — `test/test_filter_engine.log` и
`test/test_producer_lifecycle.log`. `/tmp` не переживёт пересоздание контейнера.

## 9. Ограничения

- Stage 2 не проверяет реальные producer bindings, доставку RabbitMQ,
  producer reload с engine, отбрасывание перед JSON или освобождение engine
  через producer destructor: эти пути ещё не подключены.
- Нет полного sanitizer-покрытия Core, длительного stress/benchmark или
  доказательства отсутствия любых гонок; concurrent destroy запрещён контрактом.
- Caller передаёт уже разобранный XML. Ограничение общего размера XML,
  поведения его DTD/entities и количества дублирующих selector nodes до
  создания XML tree не входит в engine; это задача входного слоя.
- 4 MiB ограничивает копии строк каждого объекта, а не общий peak RSS:
  DTO, engine и исходный XML могут одновременно занимать память.
- Для обычных headers Matcher линейно обходит узлы/элементы для каждого
  условия подходящих правил. Вторичный header index и performance SLA не добавлены.
- Согласование volume build artifacts с Core образа остаётся необходимым
  перед production-интеграцией. Успешная standalone проверка не устраняет
  обнаруженное на этапе 1 смешение сборок.

## 10. Будущий этап интеграции — не реализован

Следующий этап должен добавить подготовку полного producer-набора **до**
teardown активного набора. Новые операции ниже — план, не существующие API:

1. Разобрать конфигурацию в отдельные временные объекты, проверить имена
   профилей и режимы; default `legacy`, существующий `event_filter` сохранить.
2. Для каждого `rules` профиля выполнить parse/compile и сохранить engine
   с subscription plan в подготовленном наборе. Любая ошибка до переключения
   должна освобождать только этот набор и сохранять работающие профили.
3. Установить явного владельца engine в новом профиле до публикации bindings.
   Договориться об ошибках активации после teardown: предварительная компиляция
   сама по себе не обеспечивает rollback транспорта или атомарную замену.
4. Зарегистрировать уникальный plan через `switch_event_bind_removable()`
   с subclass ANY/NULL и сохранить каждый handle за профилем. При ALL не
   регистрировать дополнительные конкретные bindings. Ноль rules — ноль bindings.
5. В `rules` callback вызвать Matcher до выделения AMQP message и JSON.
   Несколько совпавших правил дают одно решение; один binding на доставку
   устраняет overlap подписок в `rules`. Legacy-дубли не менять.
6. При частичном отказе активации и при destroy соблюдать барьеры этапа 1:
   сначала индивидуальные unbind, затем stop/join sender; engine освобождать
   вместе с профилем только после успешных барьеров. При ошибке cleanup
   сохранять engine с остальными ресурсами retained profile.

Публикацию, замену и destroy engine нельзя выполнять конкурентно с читателями
без внешнего барьера. Существующий lifecycle mutex сериализует управление,
а Core unbind обеспечивает барьер callback; Matcher не должен брать этот mutex.
В текущем этапе ни один из перечисленных production-путей не изменён.
