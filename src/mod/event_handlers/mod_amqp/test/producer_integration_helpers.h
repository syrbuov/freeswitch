/* Included only by the integration test translation unit. */

static void integration_reset(void)
{
	callbacks = message_allocations = enqueue_calls = engines_destroyed = logger_seen = 0;
	queue_creations = thread_creations = hash_insertions = 0;
	expected_old_unbinds = new_binding_before_old_removed = persistent_unbind_failure = 0;
	config_snapshot = NULL;
	fail_other_thread = fail_queue_at = fail_thread_at = fail_hash_at = 0;
	fail_adjacent_mutex = 0;
	worker_mode = WORKER_IDLE;
	worker_io_entered = worker_sleep_entered = worker_queue_entered = 0;
	worker_release_io = worker_release_sleep = worker_release_queue = 0;
}

static void integration_dispatch(switch_event_t *event)
{
	/* Count only explicitly injected events; exclude ambient Core heartbeat/log events. */
	if (!switch_event_get_header(event, "AMQP-Lifecycle-Test")) return;
	switch_mutex_lock(test_mutex);
	callbacks++;
	switch_mutex_unlock(test_mutex);
	mod_amqp_producer_event_handler(event);
}

static void *integration_message_alloc(size_t bytes)
{
	switch_mutex_lock(test_mutex);
	message_allocations++;
	switch_mutex_unlock(test_mutex);
	return malloc(bytes);
}

static switch_status_t integration_enqueue(switch_queue_t *queue, void *message)
{
	switch_mutex_lock(test_mutex);
	enqueue_calls++;
	switch_mutex_unlock(test_mutex);
	return switch_queue_trypush(queue, message);
}

static void integration_engine_destroy(mod_amqp_filter_engine_t **engine)
{
	if (engine && *engine) {
		switch_mutex_lock(test_mutex);
		engines_destroyed++;
		switch_mutex_unlock(test_mutex);
	}
	mod_amqp_filter_engine_destroy(engine);
}

static switch_xml_t integration_open_cfg(const char *file, switch_xml_t *cfg, switch_event_t *params)
{
	(void)file;
	(void)params;
	*cfg = switch_xml_parse_str_dynamic((char *)(config_snapshot ? config_snapshot : "<configuration/>"), SWITCH_TRUE);
	return *cfg;
}

static switch_status_t integration_logger(const switch_log_node_t *node, switch_log_level_t level)
{
	switch_status_t result = mod_amqp_logging_recv(node, level);
	if (node->content && strstr(node->content, "amqp-integration-log-marker")) {
		switch_mutex_lock(test_mutex);
		logger_seen++;
		switch_thread_cond_broadcast(test_cond);
		switch_mutex_unlock(test_mutex);
	}
	return result;
}

static void *SWITCH_THREAD_FUNC integration_idle(switch_thread_t *thread, void *data)
{
	(void)data;
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

static switch_status_t integration_other_thread(switch_thread_t **thread, switch_threadattr_t *attr,
	switch_thread_start_t start, void *data, switch_memory_pool_t *pool)
{
	if (fail_other_thread) {
		*thread = (switch_thread_t *)data;
		return SWITCH_STATUS_GENERR;
	}
	if (worker_mode != WORKER_IDLE) {
		/* Queue wait needs an active connection, but never dereferences it. */
		if (worker_mode == WORKER_QUEUE_WAIT && start == mod_amqp_logging_thread) {
			((mod_amqp_logging_profile_t *)data)->conn_active = (mod_amqp_connection_t *)data;
		}
		return switch_thread_create(thread, attr, start, data, pool);
	}
	/* Adjacent workers do no network I/O; their real create/destroy/recv paths run. */
	return switch_thread_create(thread, attr, integration_idle, data, pool);
}

static void integration_cleanup(void)
{
	switch_hash_index_t *hi = NULL;
	mod_amqp_logging_profile_t *logging;
	mod_amqp_command_profile_t *command;
	if (mod_amqp_globals.logging_bound) {
		switch_assert(switch_log_unbind_logger(integration_logger) == SWITCH_STATUS_SUCCESS);
		mod_amqp_globals.logging_bound = SWITCH_FALSE;
	}
	while (mod_amqp_globals.logging_hash && (hi = switch_core_hash_first_iter(mod_amqp_globals.logging_hash, hi))) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&logging);
		switch_assert(mod_amqp_logging_destroy(&logging) == SWITCH_STATUS_SUCCESS);
	}
	while (mod_amqp_globals.command_hash && (hi = switch_core_hash_first_iter(mod_amqp_globals.command_hash, hi))) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&command);
		switch_assert(mod_amqp_command_destroy(&command) == SWITCH_STATUS_SUCCESS);
	}
}

static switch_status_t integration_profile(const char *name, const char *body)
{
	char text[8192];
	switch_xml_t xml;
	switch_status_t status;
	switch_snprintf(text, sizeof(text), "<profile><params><param name='format_fields' value='#lifecycle'/></params>%s</profile>", body);
	xml = switch_xml_parse_str_dynamic(text, SWITCH_TRUE);
	switch_assert(xml && !*switch_xml_error(xml));
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	status = mod_amqp_producer_create((char *)name, xml);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	switch_xml_free(xml);
	return status;
}

static switch_status_t integration_reload(const char *snapshot)
{
	switch_stream_handle_t stream = { 0 };
	switch_status_t status;
	config_snapshot = snapshot;
	SWITCH_STANDARD_STREAM(stream);
	status = amqp_reload(NULL, NULL, &stream);
	if (status == SWITCH_STATUS_SUCCESS && stream.data &&
		!strcmp((const char *)stream.data, "+OK mod_amqp configuration reloaded\n")) {
		status = SWITCH_STATUS_SUCCESS;
	} else {
		status = SWITCH_STATUS_GENERR;
	}
	switch_safe_free(stream.data);
	return status;
}

static mod_amqp_producer_profile_t *integration_find(const char *name)
{
	return switch_core_hash_find(mod_amqp_globals.producer_hash, name);
}

static void integration_value(const char *value)
{
	switch_event_t *event = NULL;
	switch_assert(switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, "amqp::lifecycle") == SWITCH_STATUS_SUCCESS);
	switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "AMQP-Lifecycle-Test", "true");
	if (value) switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "tenant", value);
	switch_event_deliver(&event);
}

static void *SWITCH_THREAD_FUNC integration_flood(switch_thread_t *thread, void *data)
{
	int i;
	(void)data;
	for (i = 0; i < 500; i++) deliver(SWITCH_EVENT_DTMF, NULL);
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

#define RULE_DTMF "<filter mode='rules'><rule><event name='DTMF'/></rule></filter>"
#define PROFILE_NEW "<profile name='new'>" RULE_DTMF "</profile>"
#define CONFIG_NEW "<configuration><producers>" PROFILE_NEW "</producers></configuration>"
