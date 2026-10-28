/* Production command/logging loops with deterministic network/queue wrappers.
 * Included only by the isolated integration executable. */

static switch_status_t integration_connection_open(mod_amqp_connection_t *connections,
	mod_amqp_connection_t **active, char *name, char *custom_attr, mod_amqp_io_t *io)
{
	(void)connections; (void)active; (void)name; (void)custom_attr; (void)io;
	switch_mutex_lock(test_mutex);
	worker_io_entered++;
	switch_thread_cond_broadcast(test_cond);
	while (worker_mode == WORKER_IO_BLOCK && !worker_release_io) {
		switch_thread_cond_wait(test_cond, test_mutex);
	}
	switch_mutex_unlock(test_mutex);
	return SWITCH_STATUS_GENERR;
}

static switch_status_t integration_adjacent_mutex_init(switch_mutex_t **mutex,
	unsigned int flags, switch_memory_pool_t *pool)
{
	if (fail_adjacent_mutex) {
		*mutex = (switch_mutex_t *)pool;
		return SWITCH_STATUS_GENERR;
	}
	return switch_mutex_init(mutex, flags, pool);
}

static void integration_worker_sleep(switch_interval_time_t interval)
{
	(void)interval;
	switch_mutex_lock(test_mutex);
	worker_sleep_entered++;
	switch_thread_cond_broadcast(test_cond);
	while (worker_mode == WORKER_SLEEP_BLOCK && !worker_release_sleep) {
		switch_thread_cond_wait(test_cond, test_mutex);
	}
	switch_mutex_unlock(test_mutex);
	/* Bound the synthetic reconnect loop without masking its stop check. */
	switch_sleep(1000);
}

static void integration_worker_wait(switch_mutex_t *mutex, switch_thread_cond_t *cond,
								   switch_bool_t *running, int milliseconds)
{
	set_counter(&worker_sleep_entered, read_counter(&worker_sleep_entered) + 1);
	mod_amqp_worker_wait(mutex, cond, running, milliseconds);
}

static switch_status_t integration_queue_pop_timeout(switch_queue_t *queue, void **data,
	switch_interval_time_t timeout)
{
	(void)queue; (void)data; (void)timeout;
	switch_mutex_lock(test_mutex);
	worker_queue_entered++;
	switch_thread_cond_broadcast(test_cond);
	while (!worker_release_queue) {
		switch_thread_cond_wait(test_cond, test_mutex);
	}
	switch_mutex_unlock(test_mutex);
	return SWITCH_STATUS_TIMEOUT;
}

static switch_status_t worker_create_profile(switch_bool_t command)
{
	switch_xml_t xml = switch_xml_parse_str_dynamic(
		"<profile><params><param name='reconnect_interval_ms' value='60000'/></params></profile>", SWITCH_TRUE);
	switch_status_t status;
	switch_assert(xml);
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	status = command ? mod_amqp_command_create("worker", xml) : mod_amqp_logging_create("worker", xml);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	switch_xml_free(xml);
	return status;
}

typedef struct {
	switch_bool_t command;
	void *profile;
	switch_status_t status;
} worker_destroy_context_t;

static void *SWITCH_THREAD_FUNC worker_destroy_thread(switch_thread_t *thread, void *data)
{
	worker_destroy_context_t *context = data;
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	if (context->command) {
		mod_amqp_command_profile_t *profile = context->profile;
		context->status = mod_amqp_command_destroy(&profile);
		context->profile = profile;
	} else {
		mod_amqp_logging_profile_t *profile = context->profile;
		context->status = mod_amqp_logging_destroy(&profile);
		context->profile = profile;
	}
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	set_counter(&destroy_done, 1);
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

static switch_bool_t worker_stop_seen(worker_destroy_context_t *context)
{
	switch_time_t deadline = switch_time_now() + 3000000;
	while (switch_time_now() < deadline) {
		if (context->command) {
			if (!mod_amqp_command_is_running(context->profile)) return SWITCH_TRUE;
		} else if (!mod_amqp_logging_is_running(context->profile)) {
			return SWITCH_TRUE;
		}
		switch_sleep(1000);
	}
	return SWITCH_FALSE;
}

static switch_bool_t worker_state_mutex_available(worker_destroy_context_t *context)
{
	switch_mutex_t *mutex = context->command ?
		((mod_amqp_command_profile_t *)context->profile)->mutex :
		((mod_amqp_logging_profile_t *)context->profile)->mutex;
	if (switch_mutex_trylock(mutex) != SWITCH_STATUS_SUCCESS) return SWITCH_FALSE;
	switch_mutex_unlock(mutex);
	return SWITCH_TRUE;
}
