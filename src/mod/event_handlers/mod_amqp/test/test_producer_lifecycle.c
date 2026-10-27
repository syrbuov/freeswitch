/* mod_amqp producer lifecycle tests. No RabbitMQ broker is required.
 *
 * Compile the production producer implementation with narrow fault-injection
 * wrappers. Event binding, delivery, unbinding, queues, pools and joins still
 * use libfreeswitch. Only the network sender is replaced with a joinable worker
 * which observes the same synchronized stop flag. No production test hooks.
 */
#include "mod_amqp.h"
#include <test/switch_test.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_amqp_shutdown);

static switch_status_t lifecycle_bind(const char *, switch_event_types_t, const char *,
										switch_event_callback_t, void *, switch_event_node_t **);
static switch_status_t lifecycle_unbind(switch_event_node_t **);
static switch_status_t lifecycle_thread_create(switch_thread_t **, switch_threadattr_t *,
											 switch_thread_start_t, void *, switch_memory_pool_t *);
static switch_status_t lifecycle_join(switch_status_t *, switch_thread_t *);
static switch_status_t lifecycle_queue_create(switch_queue_t **, unsigned int, switch_memory_pool_t *);
static switch_status_t lifecycle_mutex_init(switch_mutex_t **, unsigned int, switch_memory_pool_t *);
static switch_status_t lifecycle_hash_insert(switch_hash_t *, const char *, const void *);
static switch_status_t lifecycle_serialize(switch_event_t *, char **);

#ifdef MOD_AMQP_INTEGRATION
static int callbacks, message_allocations, enqueue_calls, engines_destroyed, logger_seen;
static int queue_creations, thread_creations, hash_insertions;
static int new_binding_before_old_removed, expected_old_unbinds;
static const char *config_snapshot;
static int persistent_unbind_failure, fail_other_thread;
static int fail_queue_at, fail_thread_at, fail_hash_at;

static void integration_dispatch(switch_event_t *);
static void *integration_message_alloc(size_t);
static switch_status_t integration_enqueue(switch_queue_t *, void *);
static void integration_engine_destroy(mod_amqp_filter_engine_t **);
#undef switch_malloc
#define switch_malloc(p, size) do { (p) = integration_message_alloc(size); switch_assert(p); } while (0)
#define switch_queue_trypush integration_enqueue
#define mod_amqp_filter_engine_destroy integration_engine_destroy
#endif
#define switch_event_bind_removable lifecycle_bind
#define switch_event_unbind lifecycle_unbind
#define switch_thread_create lifecycle_thread_create
#define switch_thread_join lifecycle_join
#define switch_queue_create lifecycle_queue_create
#define switch_mutex_init lifecycle_mutex_init
#define switch_event_serialize_json lifecycle_serialize
#undef switch_core_hash_insert
#define switch_core_hash_insert lifecycle_hash_insert
#include "../mod_amqp_producer.c"
#undef switch_event_bind_removable
#undef switch_event_unbind
#undef switch_thread_create
#undef switch_thread_join
#undef switch_queue_create
#undef switch_mutex_init
#undef switch_event_serialize_json
#undef switch_core_hash_insert
#define switch_core_hash_insert(_h, _k, _d) switch_core_hash_insert_destructor(_h, _k, _d, NULL)

#ifdef MOD_AMQP_INTEGRATION
#undef switch_malloc
#define switch_malloc(p, size) do { (p) = malloc(size); switch_assert(p); } while (0)
#undef switch_queue_trypush
#undef mod_amqp_filter_engine_destroy
static switch_xml_t integration_open_cfg(const char *, switch_xml_t *, switch_event_t *);
static switch_status_t integration_logger(const switch_log_node_t *, switch_log_level_t);
#define switch_xml_open_cfg integration_open_cfg
#define mod_amqp_logging_recv integration_logger
#include "../mod_amqp_utils.c"
#include "../mod_amqp.c"
#undef switch_xml_open_cfg
#undef mod_amqp_logging_recv
static switch_status_t integration_other_thread(switch_thread_t **, switch_threadattr_t *, switch_thread_start_t, void *, switch_memory_pool_t *);
#define switch_thread_create integration_other_thread
#define switch_thread_join lifecycle_join
#include "../mod_amqp_logging.c"
#include "../mod_amqp_command.c"
#undef switch_thread_join
#undef switch_thread_create
#endif

static switch_mutex_t *test_mutex;
static switch_thread_cond_t *test_cond;
static int bind_calls, join_calls, fail_bind_at, fail_thread, fail_queue, fail_hash, fail_mutex;
static int fail_join, fail_unbind, unbind_calls, serialized, sender_stopped;
static int hold_callback, callback_entered, release_callback;
static int hold_sender, release_sender, destroy_done;

static int read_counter(int *value)
{
	int result;
	switch_mutex_lock(test_mutex);
	result = *value;
	switch_mutex_unlock(test_mutex);
	return result;
}

static void set_counter(int *value, int new_value)
{
	switch_mutex_lock(test_mutex);
	*value = new_value;
	switch_thread_cond_broadcast(test_cond);
	switch_mutex_unlock(test_mutex);
}

static int await_counter(int *value, int minimum)
{
	switch_time_t deadline = switch_time_now() + 3000000;
	int result;
	switch_mutex_lock(test_mutex);
	while (*value < minimum && switch_time_now() < deadline) {
		switch_thread_cond_timedwait(test_cond, test_mutex, 10000);
	}
	result = *value >= minimum;
	switch_mutex_unlock(test_mutex);
	return result;
}

static switch_status_t lifecycle_serialize(switch_event_t *event, char **json)
{
	if (switch_event_get_header(event, "AMQP-Lifecycle-Test")) {
		switch_mutex_lock(test_mutex);
		serialized++;
		callback_entered = 1;
		switch_thread_cond_broadcast(test_cond);
		while (hold_callback && !release_callback) {
			switch_thread_cond_wait(test_cond, test_mutex);
		}
		switch_mutex_unlock(test_mutex);
	}
	return switch_event_serialize_json(event, json);
}

static switch_status_t lifecycle_bind(const char *id, switch_event_types_t event, const char *subclass,
										switch_event_callback_t callback, void *data, switch_event_node_t **node)
{
#ifdef MOD_AMQP_INTEGRATION
	if (expected_old_unbinds && read_counter(&unbind_calls) < expected_old_unbinds) new_binding_before_old_removed++;
#endif
	bind_calls++;
	if (bind_calls == fail_bind_at) {
		*node = NULL;
		return SWITCH_STATUS_GENERR;
	}
#ifdef MOD_AMQP_INTEGRATION
	callback = integration_dispatch;
#endif
	return switch_event_bind_removable(id, event, subclass, callback, data, node);
}

static switch_status_t lifecycle_unbind(switch_event_node_t **node)
{
	int fail;
	switch_mutex_lock(test_mutex);
	unbind_calls++;
	fail = fail_unbind;
#ifdef MOD_AMQP_INTEGRATION
	if (persistent_unbind_failure) fail = 1;
#endif
	fail_unbind = 0;
	switch_thread_cond_broadcast(test_cond);
	switch_mutex_unlock(test_mutex);
	return fail ? SWITCH_STATUS_GENERR : switch_event_unbind(node);
}

static void *SWITCH_THREAD_FUNC lifecycle_sender(switch_thread_t *thread, void *data)
{
	mod_amqp_producer_profile_t *profile = data;
	while (mod_amqp_producer_is_running(profile)) {
		switch_sleep(1000);
	}
	switch_mutex_lock(test_mutex);
	sender_stopped++;
	switch_thread_cond_broadcast(test_cond);
	while (hold_sender && !release_sender) {
		switch_thread_cond_wait(test_cond, test_mutex);
	}
	switch_mutex_unlock(test_mutex);
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

static switch_status_t lifecycle_thread_create(switch_thread_t **thread, switch_threadattr_t *attr,
											 switch_thread_start_t start, void *data, switch_memory_pool_t *pool)
{
#ifdef MOD_AMQP_INTEGRATION
	thread_creations++;
	if (thread_creations == fail_thread_at) return SWITCH_STATUS_GENERR;
#endif
	if (fail_thread) {
		/* APR may write its output even when no thread was successfully started. */
		*thread = (switch_thread_t *)data;
		return SWITCH_STATUS_GENERR;
	}
	switch_assert(start == mod_amqp_producer_thread);
	return switch_thread_create(thread, attr, lifecycle_sender, data, pool);
}

static switch_status_t lifecycle_join(switch_status_t *status, switch_thread_t *thread)
{
	join_calls++;
	if (fail_join) {
		fail_join = 0;
		return SWITCH_STATUS_GENERR;
	}
	return switch_thread_join(status, thread);
}

static switch_status_t lifecycle_queue_create(switch_queue_t **queue, unsigned int capacity, switch_memory_pool_t *pool)
{
#ifdef MOD_AMQP_INTEGRATION
	queue_creations++;
	if (queue_creations == fail_queue_at) return SWITCH_STATUS_GENERR;
#endif
	if (fail_queue) {
		/* The real queue API also publishes its output before initialization. */
		*queue = (switch_queue_t *)pool;
		return SWITCH_STATUS_GENERR;
	}
	return switch_queue_create(queue, capacity, pool);
}

static switch_status_t lifecycle_mutex_init(switch_mutex_t **mutex, unsigned int flags, switch_memory_pool_t *pool)
{
	if (fail_mutex) {
		*mutex = (switch_mutex_t *)pool;
		return SWITCH_STATUS_GENERR;
	}
	return switch_mutex_init(mutex, flags, pool);
}

static switch_status_t lifecycle_hash_insert(switch_hash_t *hash, const char *name, const void *data)
{
#ifdef MOD_AMQP_INTEGRATION
	hash_insertions++;
	if (hash_insertions == fail_hash_at) return SWITCH_STATUS_GENERR;
#endif
	if (fail_hash) return SWITCH_STATUS_GENERR;
	return switch_core_hash_insert_destructor(hash, name, data, NULL);
}

static switch_status_t create_profile(const char *name, const char *filter)
{
	switch_xml_t xml, params, param;
	switch_status_t status;

	xml = switch_xml_new("profile");
	params = switch_xml_add_child_d(xml, "params", 0);
	param = switch_xml_add_child_d(params, "param", 0);
	switch_xml_set_attr_d(param, "name", "format_fields");
	switch_xml_set_attr_d(param, "value", "#lifecycle");
	if (filter) {
		param = switch_xml_add_child_d(params, "param", 1);
		switch_xml_set_attr_d(param, "name", "event_filter");
		switch_xml_set_attr_d(param, "value", filter);
	}
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	status = mod_amqp_producer_create((char *)name, xml);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	switch_xml_free(xml);
	return status;
}

static switch_status_t destroy_profile(mod_amqp_producer_profile_t **profile)
{
	switch_status_t status;
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	status = mod_amqp_producer_destroy(profile);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	return status;
}

static void deliver(switch_event_types_t id, const char *subclass)
{
	switch_event_t *event = NULL;
	switch_assert(switch_event_create_subclass(&event, id, subclass) == SWITCH_STATUS_SUCCESS);
	switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "AMQP-Lifecycle-Test", "true");
	switch_event_deliver(&event);
}

static void *SWITCH_THREAD_FUNC delivery_thread(switch_thread_t *thread, void *data)
{
	(void)data;
	deliver(SWITCH_EVENT_DTMF, NULL);
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

typedef struct {
	mod_amqp_producer_profile_t *profile;
	switch_status_t status;
} destroy_context_t;

static void *SWITCH_THREAD_FUNC destroy_thread(switch_thread_t *thread, void *data)
{
	destroy_context_t *context = data;
	context->status = destroy_profile(&context->profile);
	set_counter(&destroy_done, 1);
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

#ifdef MOD_AMQP_INTEGRATION
#include "producer_integration_helpers.h"
#endif

FST_BEGIN()
{
#ifdef MOD_AMQP_INTEGRATION
	switch_core_flag_t test_flags = 0; /* Exercise the real logger dispatch. */
#else
	switch_core_flag_t test_flags = SCF_LOG_DISABLE;
#endif
	/* Empty modules.conf means scan mod_dir in Core. Point it at a directory
	 * containing only the test XML, never installed service modules. */
	SWITCH_GLOBAL_dirs.mod_dir = strdup(SWITCH_TEST_BASE_DIR_FOR_CONF "/conf");
	if (fst_init_core_and_modload("conf", NULL, 0, test_flags) != SWITCH_STATUS_SUCCESS) {
		fprintf(stderr, "Cannot initialize FreeSWITCH event engine\n");
		exit(1);
	}

	switch_assert(switch_event_running() == SWITCH_STATUS_SUCCESS);

	/* FST_SUITE_BEGIN declares its context; keep it at the start of a scope. */
	{
	FST_SUITE_BEGIN(mod_amqp_producer_lifecycle)
	{
		FST_SETUP_BEGIN()
		{
			memset(&mod_amqp_globals, 0, sizeof(mod_amqp_globals));
			switch_core_new_memory_pool(&fst_pool);
			mod_amqp_globals.pool = fst_pool;
			switch_mutex_init(&mod_amqp_globals.lifecycle_mutex, SWITCH_MUTEX_UNNESTED, fst_pool);
			switch_mutex_init(&test_mutex, SWITCH_MUTEX_NESTED, fst_pool);
			switch_thread_cond_create(&test_cond, fst_pool);
			switch_core_hash_init(&mod_amqp_globals.producer_hash);
			switch_core_hash_init(&mod_amqp_globals.command_hash);
			switch_core_hash_init(&mod_amqp_globals.logging_hash);
			bind_calls = join_calls = fail_bind_at = fail_thread = fail_queue = fail_hash = fail_mutex = 0;
			fail_join = fail_unbind = unbind_calls = serialized = sender_stopped = 0;
			hold_callback = callback_entered = release_callback = 0;
			hold_sender = release_sender = destroy_done = 0;
#ifdef MOD_AMQP_INTEGRATION
			integration_reset();
#endif
		}
		FST_SETUP_END()

		FST_TEARDOWN_BEGIN()
		{
			switch_hash_index_t *hi = NULL;
			mod_amqp_producer_profile_t *profile;
			fail_join = fail_unbind = 0;
#ifdef MOD_AMQP_INTEGRATION
			persistent_unbind_failure = 0;
#endif
			while (mod_amqp_globals.producer_hash && (hi = switch_core_hash_first_iter(mod_amqp_globals.producer_hash, hi))) {
				switch_core_hash_this(hi, NULL, NULL, (void **)&profile);
				switch_assert(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
			}
#ifdef MOD_AMQP_INTEGRATION
			integration_cleanup();
#else
			if (mod_amqp_globals.logging_bound) switch_log_unbind_logger(mod_amqp_logging_recv);
#endif
			if (mod_amqp_globals.producer_hash) switch_core_hash_destroy(&mod_amqp_globals.producer_hash);
			if (mod_amqp_globals.command_hash) switch_core_hash_destroy(&mod_amqp_globals.command_hash);
			if (mod_amqp_globals.logging_hash) switch_core_hash_destroy(&mod_amqp_globals.logging_hash);
			switch_core_destroy_memory_pool(&fst_pool);
		}
		FST_TEARDOWN_END()

#ifdef MOD_AMQP_INTEGRATION
#include "producer_integration_cases.h"
#else
		FST_TEST_BEGIN(null_and_repeated_destroy)
		{
			mod_amqp_producer_profile_t *profile = NULL;
			fst_check(destroy_profile(NULL) == SWITCH_STATUS_SUCCESS);
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
			fst_check(create_profile("test", "DTMF") == SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "test");
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
			fst_check(profile == NULL);
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(independent_profiles_and_legacy_duplicates)
		{
			mod_amqp_producer_profile_t *first;
			fst_check(create_profile("first", "ALL,DTMF,DTMF") == SWITCH_STATUS_SUCCESS);
			fst_check(create_profile("second", "DTMF") == SWITCH_STATUS_SUCCESS);
			deliver(SWITCH_EVENT_DTMF, NULL);
			fst_check(read_counter(&serialized) == 4);
			first = switch_core_hash_find(mod_amqp_globals.producer_hash, "first");
			fst_check(destroy_profile(&first) == SWITCH_STATUS_SUCCESS);
			deliver(SWITCH_EVENT_DTMF, NULL);
			fst_check(read_counter(&serialized) == 5);
			fst_check(read_counter(&unbind_calls) == 3);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(legacy_defaults_empty_and_subclass)
		{
			mod_amqp_producer_profile_t *profile;
			fst_check(create_profile("default", NULL) == SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "default");
			fst_check(profile->event_subscriptions == 1 && profile->events[0].id == SWITCH_EVENT_ALL);
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
			fst_check(create_profile("empty", "") == SWITCH_STATUS_SUCCESS);
			fst_check(create_profile("custom", "SWITCH_EVENT_CUSTOM^amqp::lifecycle") == SWITCH_STATUS_SUCCESS);
			deliver(SWITCH_EVENT_CUSTOM, "amqp::lifecycle");
			deliver(SWITCH_EVENT_CUSTOM, "amqp::other");
			fst_check(read_counter(&serialized) == 1);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(duplicate_name_does_not_replace_owner)
		{
			mod_amqp_producer_profile_t *owner;
			fst_check(create_profile("same", "DTMF") == SWITCH_STATUS_SUCCESS);
			owner = switch_core_hash_find(mod_amqp_globals.producer_hash, "same");
			fst_check(create_profile("same", "ALL") != SWITCH_STATUS_SUCCESS);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "same") == owner);
			fst_check(bind_calls == 1);
			deliver(SWITCH_EVENT_DTMF, NULL);
			fst_check(read_counter(&serialized) == 1);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(destroy_does_not_delete_foreign_hash_entry)
		{
			mod_amqp_producer_profile_t *original, *replacement;
			fst_check(create_profile("same", "DTMF") == SWITCH_STATUS_SUCCESS);
			original = switch_core_hash_find(mod_amqp_globals.producer_hash, "same");
			switch_core_hash_delete(mod_amqp_globals.producer_hash, "same");
			fst_check(create_profile("same", "DTMF") == SWITCH_STATUS_SUCCESS);
			replacement = switch_core_hash_find(mod_amqp_globals.producer_hash, "same");
			fst_check(destroy_profile(&original) == SWITCH_STATUS_SUCCESS);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "same") == replacement);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(partial_binding_failures)
		{
			int position;
			for (position = 1; position <= 3; position++) {
				bind_calls = 0;
				set_counter(&unbind_calls, 0);
				fail_bind_at = position;
				fst_check(create_profile("partial", "DTMF,HEARTBEAT,CUSTOM^amqp::lifecycle") != SWITCH_STATUS_SUCCESS);
				fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "partial") == NULL);
				fst_check(read_counter(&unbind_calls) == position - 1);
				deliver(SWITCH_EVENT_DTMF, NULL);
				deliver(SWITCH_EVENT_HEARTBEAT, NULL);
				deliver(SWITCH_EVENT_CUSTOM, "amqp::lifecycle");
				fst_check(read_counter(&serialized) == 0);
			}
			fst_check(join_calls == 3);
			fst_check(read_counter(&sender_stopped) == 3);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(failures_before_bindings)
		{
			fail_mutex = 1;
			fst_check(create_profile("mutex", "DTMF") != SWITCH_STATUS_SUCCESS);
			fail_mutex = 0;
			fail_queue = 1;
			fst_check(create_profile("queue", "DTMF") != SWITCH_STATUS_SUCCESS);
			fail_queue = 0;
			fail_hash = 1;
			fst_check(create_profile("hash", "DTMF") != SWITCH_STATUS_SUCCESS);
			fail_hash = 0;
			fail_thread = 1;
			fst_check(create_profile("thread", "DTMF") != SWITCH_STATUS_SUCCESS);
			fst_check(switch_core_hash_empty(mod_amqp_globals.producer_hash));
			fst_check(bind_calls == 0 && join_calls == 0);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(partial_create_with_failed_cleanup_remains_reachable)
		{
			mod_amqp_producer_profile_t *profile;
			fail_bind_at = 2;
			fail_join = 1;
			fst_check(create_profile("partial-join", "DTMF,HEARTBEAT") != SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "partial-join");
			fst_check(profile != NULL && profile->producer_thread != NULL);
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
			bind_calls = 0;
			fail_unbind = 1;
			fst_check(create_profile("partial-unbind", "DTMF,HEARTBEAT") != SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "partial-unbind");
			fst_check(profile != NULL && profile->event_nodes[0] != NULL);
			deliver(SWITCH_EVENT_DTMF, NULL);
			fst_check(read_counter(&serialized) == 0);
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(join_failure_retains_profile_for_retry)
		{
			mod_amqp_producer_profile_t *profile;
			fst_check(create_profile("join", "DTMF") == SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "join");
			fail_join = 1;
			fst_check(destroy_profile(&profile) != SWITCH_STATUS_SUCCESS);
			fst_check(profile != NULL && profile->producer_thread != NULL);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "join") == profile);
			fst_check(!mod_amqp_producer_is_running(profile));
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
			fst_check(profile == NULL);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(unbind_failure_retains_profile_for_retry)
		{
			mod_amqp_producer_profile_t *profile;
			fst_check(create_profile("unbind", "DTMF,HEARTBEAT") == SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "unbind");
			fail_unbind = 1;
			fst_check(destroy_profile(&profile) != SWITCH_STATUS_SUCCESS);
			fst_check(profile != NULL && profile->event_nodes[0] != NULL);
			fst_check(profile->event_nodes[1] == NULL && profile->producer_thread == NULL);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "unbind") == profile);
			deliver(SWITCH_EVENT_DTMF, NULL);
			fst_check(read_counter(&serialized) == 0);
			fst_check(destroy_profile(&profile) == SWITCH_STATUS_SUCCESS);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(destroy_waits_for_callback_and_rejects_concurrent_reload)
		{
			switch_thread_t *delivery, *destroyer;
			switch_status_t status;
			destroy_context_t context;
			int entered, unbinding, completed;
			fst_check(create_profile("blocked", "DTMF") == SWITCH_STATUS_SUCCESS);
			context.profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "blocked");
			set_counter(&hold_callback, 1);
			switch_assert(switch_thread_create(&delivery, NULL, delivery_thread, NULL, fst_pool) == SWITCH_STATUS_SUCCESS);
			entered = await_counter(&callback_entered, 1);
			switch_assert(switch_thread_create(&destroyer, NULL, destroy_thread, &context, fst_pool) == SWITCH_STATUS_SUCCESS);
			unbinding = await_counter(&unbind_calls, 1);
			completed = read_counter(&destroy_done);
			fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
			set_counter(&release_callback, 1);
			switch_thread_join(&status, delivery);
			switch_thread_join(&status, destroyer);
			fst_check(entered && unbinding && !completed);
			fst_check(context.status == SWITCH_STATUS_SUCCESS && context.profile == NULL);
			deliver(SWITCH_EVENT_DTMF, NULL);
			fst_check(read_counter(&serialized) == 1);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(destroy_waits_for_sender_exit)
		{
			switch_thread_t *destroyer;
			switch_status_t status;
			destroy_context_t context;
			int stopped, completed;
			fst_check(create_profile("sender", "DTMF") == SWITCH_STATUS_SUCCESS);
			context.profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "sender");
			set_counter(&hold_sender, 1);
			switch_assert(switch_thread_create(&destroyer, NULL, destroy_thread, &context, fst_pool) == SWITCH_STATUS_SUCCESS);
			stopped = await_counter(&sender_stopped, 1);
			completed = read_counter(&destroy_done);
			set_counter(&release_sender, 1);
			switch_thread_join(&status, destroyer);
			fst_check(stopped && !completed);
			fst_check(context.status == SWITCH_STATUS_SUCCESS && context.profile == NULL);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(repeated_reload_removes_owned_bindings)
		{
			int iteration;
			for (iteration = 0; iteration < 10; iteration++) {
				fst_check(create_profile("reload", "DTMF,CUSTOM^amqp::lifecycle") == SWITCH_STATUS_SUCCESS);
				fst_check(mod_amqp_do_config(SWITCH_TRUE) == SWITCH_STATUS_SUCCESS);
				fst_check(switch_core_hash_empty(mod_amqp_globals.producer_hash));
				deliver(SWITCH_EVENT_DTMF, NULL);
			}
			fst_check(read_counter(&serialized) == 0);
			fst_check(read_counter(&unbind_calls) == 20);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(reload_failure_retains_failed_owner)
		{
			mod_amqp_producer_profile_t *profile;
			fst_check(create_profile("retained", "DTMF") == SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "retained");
			fail_join = 1;
			fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "retained") == profile);
			fst_check(mod_amqp_do_config(SWITCH_TRUE) == SWITCH_STATUS_SUCCESS);
			fst_check(switch_core_hash_empty(mod_amqp_globals.producer_hash));
		}
		FST_TEST_END()

		FST_TEST_BEGIN(command_worker_reload_is_rejected_before_teardown)
		{
			mod_amqp_command_profile_t command = { 0 };
			fst_check(create_profile("preserved", "DTMF") == SWITCH_STATUS_SUCCESS);
			switch_mutex_init(&command.mutex, SWITCH_MUTEX_NESTED, fst_pool);
			command.command_thread_id = switch_thread_self();
			command.command_thread_started = SWITCH_TRUE;
			switch_core_hash_insert(mod_amqp_globals.command_hash, "caller", &command);
			fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "preserved") != NULL);
			switch_core_hash_delete(mod_amqp_globals.command_hash, "caller");
		}
		FST_TEST_END()

		FST_TEST_BEGIN(reentrant_reload_is_rejected_before_teardown)
		{
			fst_check(create_profile("preserved", "DTMF") == SWITCH_STATUS_SUCCESS);
			switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
			fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
			switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "preserved") != NULL);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(shutdown_removes_individual_bindings)
		{
			fst_check(create_profile("one", "DTMF") == SWITCH_STATUS_SUCCESS);
			fst_check(create_profile("two", "DTMF") == SWITCH_STATUS_SUCCESS);
			fst_check(mod_amqp_shutdown() == SWITCH_STATUS_SUCCESS);
			fst_check(mod_amqp_globals.producer_hash == NULL);
			fst_check(read_counter(&unbind_calls) == 2);
			deliver(SWITCH_EVENT_DTMF, NULL);
			fst_check(read_counter(&serialized) == 0);
			fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(shutdown_failure_pins_module_and_retains_profile)
		{
			mod_amqp_producer_profile_t *profile;
			fst_check(create_profile("retained", "DTMF") == SWITCH_STATUS_SUCCESS);
			profile = switch_core_hash_find(mod_amqp_globals.producer_hash, "retained");
			fail_join = 1;
			fst_check(mod_amqp_shutdown() == SWITCH_STATUS_NOUNLOAD);
			fst_check(switch_core_hash_find(mod_amqp_globals.producer_hash, "retained") == profile);
			fst_check(mod_amqp_shutdown() == SWITCH_STATUS_SUCCESS);
		}
		FST_TEST_END()
#endif
	}
	FST_SUITE_END()
	}
	switch_core_destroy();
}
FST_END()
