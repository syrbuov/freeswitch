> Продолжение: [диагностика профилей и восстановление TCP](filter-engine-profile-diagnostics.md). DNS/TLS отложены пользователем.
> В ветке local-test [прежние command-профили включены отдельно](legacy-local-commands.md);
> описанное ниже отключение commands относится к базовому этапу producer/logging.

# mod_amqp: producer/logging lifecycle без изменения Core

Дата: 28 октября 2026 года. Baseline: `aa7df4d6ca`.
Пользователь исключил изменения Core и выбрал временное отключение
command-профилей. Изменения этого этапа сохранены в исходниках ветки;
установленный модуль, работающие FreeSWITCH/RabbitMQ и рабочий XML не менялись.
Этот отчёт описывает текущую реализацию; permanent-политика и незакрытый
ASan из предыдущих отчётов относятся к baseline.

## Поддерживаемый контракт

- Обычная успешная загрузка возвращает `SWITCH_STATUS_SUCCESS`. Поэтому Core
  вызывает shutdown модуля при завершении процесса. Permanent при нормальной
  загрузке отменён. Динамический load/unload поддерживается из внешнего
  управляющего потока, вне event/log callbacks.
- `<commands><profile .../></commands>` не создаёт workers, подключения или
  console execution. Каждый такой профиль вызывает явное предупреждение.
  Остальная конфигурация продолжает загружаться. `amqp status` содержит
  `commands=disabled`. Это намеренное изменение совместимости: приложения,
  управляющие FreeSWITCH через AMQP commands, пока не смогут выполнять команды.
- `amqp` остаётся reload конфигурации, `amqp status` — чтением состояния.
  ACTIVE означает успешную активацию конфигурации, а не доступность брокера
  или подтверждённую доставку всех сообщений.
- Reload проверяет producer-набор до teardown. Ошибка подготовки сохраняет
  старый набор; после начала teardown rollback и переноса очередей нет.
- Shutdown ждёт владельца lifecycle вместо раннего отказа по trylock.
  Producer/logging workers и callbacks lifecycle mutex не захватывают.
  Command ingress отключён, поэтому из него невозможно запустить self-unload
  либо shutdown всего процесса на собственном worker.

## Остановка и владение I/O

Producer/logging имеют condition variable, защищённую тем же mutex, что и
running. Stop публикуется под mutex, будит reconnect wait и очередь. После
выхода из ожидания очереди sender повторно проверяет running перед отправкой.
Остатки очереди и текущего сообщения освобождаются при teardown.

AMQP-объектом до join владеет только worker. После открытия сокета он
регистрирует отдельный дублированный дескриптор. Management вызывает
`shutdown()` только этого дескриптора, чтобы разбудить заблокированные
handshake/RPC/publish, затем ждёт join. Dup сохраняет идентичность сокета,
даже если rabbitmq-c уже закрыла оригинальный fd и ОС переиспользовала номер.
Регистрация, stop и освобождение dup сериализованы profile mutex; постоянный
флаг stopped запрещает регистрацию нового сокета после запроса остановки.
Management не вызывает rabbitmq-c над объектом работающего потока.

После join удаляются owned hash entries, закрываются connections, очищаются
очереди и уничтожаются engine/pool. Закрытие connection локальное, через
`amqp_destroy_connection()`: channel/connection close RPC не ждут ответа
недоступного брокера. Это не graceful drain и не гарантия доставки сообщений,
находившихся в очереди или отправке во время reload/unload.

Нужна rabbitmq-c **0.9.0+**; проверено с установленной **0.11.0**. Настройки
connection `connect-timeout-ms` и `rpc-timeout-ms` принимают 1..60000,
по умолчанию 3000. Применяются socket-open, handshake и RPC timeout API.
Отдельный AMQP state/socket создаётся для каждой цели failover, включая
переключение TCP/TLS. Некорректный producer timeout отклоняется до teardown.

## Ошибки очистки

При ошибке unbind/join память живого владельца сохраняется. Shutdown делает
попытку остановить каждый профиль, даже если один из предыдущих retained.
Если logger unbind не выполнен, logging hash/queue не освобождаются:
останавливаются workers, но сохраняются объекты, которые ещё может читать
callback. Повторная внутренняя очистка пропускает уже удалённые ресурсы.

Failed shutdown помечается RESTART_REQUIRED и возвращает NOUNLOAD, сохраняя
DSO/pool. Ошибка первоначальной загрузки с успешным unwind возвращает GENERR;
при retained resources остаётся аварийный NOUNLOAD/RESTART_REQUIRED.

**Граница неизменённого Core остаётся:** после ошибочного Core unload
registry/API могут исчезнуть при сохранённом DSO. Возврат NOUNLOAD защищает
память, но не восстанавливает интерфейсы и не обещает безопасный повторный
CLI load/unload. Это аварийное состояние, требующее отдельного восстановления
процесса; универсальная безопасность его завершения не доказана. Нельзя
выгружать модуль принудительно из event/log callback или обходить барьеры Core.
Конкурентный forced unload проверен для конкретного внешнего reload-сценария;
это не доказательство корректности всех возможных forced unload.

## Исправления, выявленные проверками

1. **ASan при выходе APR thread.** Core-декларация `switch_thread_exit()` не
   содержит noreturn, хотя корректный APR thread exit не возвращается.
   Инструментированный caller оставлял poisoned stack при выходе через
   неинструментированный Core. Локальная аннотация в `mod_amqp.h` сообщает
   компилятору реальный контракт. Проверки ASan не отключаются. Новый
   `test/asan_thread_exit_repro.c` воспроизводит исходный sigaltstack report
   на GCC 12/libasan без FreeSWITCH; вариант с noreturn проходит.
2. **Routing key.** При отсутствии format_fields использовался
   неинициализированный буфер: под ASan реальные publish отклонялись как
   BAD_AMQP_DATA. Пустой ключ теперь корректно инициализирован. Учтён NUL
   отдельно от протокольного лимита 255 байт; bounded percent-encoding
   исключает overflow на длинных/UTF-8 headers. Слишком длинный ключ
   отклоняет событие до JSON/enqueue. Формат допустимых ключей сохранён.
3. **Logging queue overflow.** При отказе enqueue освобождаются сообщение и
   его JSON. Копирование имени файла в logging callback ограничено буфером.
   Ошибка connection name больше не печатает XML с возможными credentials.
4. **Тестовая гонка.** При быстром пробуждении logging worker destroy уже мог
   освободить профиль, пока fixture читала running. Проверка reconnect теперь
   ждёт завершения destroy и join, не читая освобождённый профиль.

## Проверки

Команды выполняются в development-контейнере; примеры ниже не устанавливают
модуль и не изменяют working service. Точные make overrides сохранены в
`hardening-artifacts/commands.md`; для текущего прогона использован тот же
установленный `libfreeswitch.so`, сборка с `-Werror`.

Итоговый прогон: **19/19 engine, 18/18 lifecycle, 42/42 integration**,
сборка `-Werror`, `make check` — exit 0. Integration ASan/UBSan/LSan и TSan —
42/42, exit 0 каждый. Все **9/9 real-DSO probes** прошли в обычной сборке,
под ASan/UBSan/LSan и под TSan (27 сценариев, каждый exit 0).
Во всех случаях `workers == joined`, `early_pool_free == 0` и
`bindings == removed`. В publish-проверках `in_publish_before_stop == 1`.
Наблюдавшееся полное завершение Core занимало примерно 2.4–3.3 секунды;
это измерение тестовой среды, не общий deadline для эксплуатации.

Компактные результаты: [lifecycle-without-core-results.txt](lifecycle-without-core-results.txt).
Полные журналы/бинарники находятся в контейнере в `/tmp/mod-amqp-lifecycle-complete-*`;
минимальный ASan reproducer — `/tmp/mod-amqp-exit-repro-final`
(unannotated exit 1 с ожидаемым ASan report, annotated exit 0). Артефакты `/tmp`
не переживут удаление контейнера; исходники воспроизведения сохранены в test.
`git diff --check` — exit 0.

```sh
cd /usr/src/freeswitch/src/mod/event_handlers/mod_amqp
MOD_AMQP_SANITIZER_TEST=test_producer_integration \
  sh test/run_filter_engine_sanitizers.sh /tmp/mod-amqp-lifecycle-complete-integration /usr/local/freeswitch/lib
python3 test/run_lifecycle_probes.py /tmp/mod-amqp-lifecycle-complete-normal
python3 test/run_lifecycle_probes.py /tmp/mod-amqp-lifecycle-complete-asan --sanitizer address,undefined
python3 test/run_lifecycle_probes.py /tmp/mod-amqp-lifecycle-complete-tsan --sanitizer thread
```

Новый runner собирает production DSO и test-only interposer в отдельный `/tmp`
каталог. Его loopback AMQP stub выполняет настоящий handshake и может перестать
отвечать на handshake/RPC или читать TCP. Выполняются обычный unload,
повторный load/unload, внешняя гонка config reload/forced unload и завершение
Core с реальными producer/logging workers. В publish-сценариях фиксируется
незавершённый настоящий amqp_basic_publish перед stop. Interposer проверяет
join каждого module worker, снятие owned bindings и отсутствие освобождения
profile pool до join. AMQP I/O/worker functions не заменяются.

Fixture даёт Core softtimer завершить асинхронную начальную калибровку перед
быстрым shutdown: без этого ранний probe воспроизвёл отдельное зависание
startup/shutdown самого Core. Код Core не менялся. Первый abort publish-probe
был ошибкой lookup в тестовом interposer (--as-needed убирал librabbitmq из
его глобальной области); исправлена линковка fixture. Эти неуспешные прогоны
не засчитывались как приёмка модуля.

## Практические границы

- DNS/NSS resolution внутри socket-open зависит от системного resolver и не
  прерывается socket shutdown. Connect timeout не является доказанным общим
  deadline для DNS. Гарантия конечного времени сетевых probes относится к
  числовому loopback IP; DNS blackhole требует отдельной проверки/решения.
- Unbind использует глобальный барьер Core и может ждать чужие callbacks.
  Абсолютного общего deadline shutdown не заявляется.
- Проверены Linux TCP и установленная rabbitmq-c. TLS и Windows ветки не
  прошли сетевую приёмку. Нет длительного stress и реальных OS/APR failures.
- Sanitizers инструментируют module/harness/interposer, но не установленный
  Core, APR и rabbitmq-c. PASS не доказывает отсутствие всех гонок в этих DSO.
- Stub не заменяет runtime-проверку с реальным RabbitMQ и пользовательским
  приложением. Publisher confirms, exactly-once и гарантированная доставка
  при сетевом отказе не добавлены. Частичный/полный module reload может терять
  queued/in-flight сообщения; очередь не переносится между поколениями.
- Перед эксплуатацией требуется учитывать отключение command-профилей и
  проверить используемые TLS/DNS настройки. Установка не выполнялась.
