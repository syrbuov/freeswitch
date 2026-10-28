FST_TEST_BEGIN(legacy_default_explicit_and_subclasses)
{
	mod_amqp_producer_profile_t *p;
	fst_check(create_profile("legacy", "ALL,DTMF,DTMF") == SWITCH_STATUS_SUCCESS);
	fst_check(integration_profile("explicit", "<filter mode='legacy'><rule/></filter>") == SWITCH_STATUS_SUCCESS);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&callbacks) == 4 && read_counter(&serialized) == 4 && read_counter(&enqueue_calls) == 4);
	p = integration_find("legacy");
	fst_check(destroy_profile(&p) == SWITCH_STATUS_SUCCESS);
	p = integration_find("explicit");
	fst_check(destroy_profile(&p) == SWITCH_STATUS_SUCCESS);
	fst_check(create_profile("subclass", "CUSTOM^amqp::lifecycle,CUSTOM") == SWITCH_STATUS_SUCCESS);
	integration_value(NULL);
	fst_check(read_counter(&callbacks) == 6);
}
FST_TEST_END()

FST_TEST_BEGIN(invalid_modes_preserve_entire_old_set)
{
	const char *bad[] = {"<filter/>", "<filter mode='Rules'/>", "<filter mode='unknown'/>",
		"<filter mode='legacy'/><filter mode='rules'/>", "<filter mode='rules'><rule/></filter>"};
	char snapshot[4096];
	size_t i;
	mod_amqp_producer_profile_t *a, *b;
	fst_check(create_profile("old-a", "DTMF") == SWITCH_STATUS_SUCCESS);
	fst_check(create_profile("old-b", "DTMF") == SWITCH_STATUS_SUCCESS);
	a = integration_find("old-a"); b = integration_find("old-b");
	for (i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
		switch_snprintf(snapshot, sizeof(snapshot), "<configuration><producers>" PROFILE_NEW "<profile name='late'>%s</profile></producers><logging><profile name='log'><params><param name='log-levels' value='err'/></params></profile></logging></configuration>", bad[i]);
		fst_check(integration_reload(snapshot) != SWITCH_STATUS_SUCCESS);
		fst_check(integration_find("old-a") == a && integration_find("old-b") == b);
		fst_check(read_counter(&unbind_calls) == 0 && bind_calls == 2);
		fst_check(switch_core_hash_empty(mod_amqp_globals.logging_hash));
		deliver(SWITCH_EVENT_DTMF, NULL);
	}
	fst_check(read_counter(&serialized) == 10);
}
FST_TEST_END()

FST_TEST_BEGIN(rules_ignore_legacy_and_match_once)
{
	const char *snapshot = "<configuration><producers><profile name='rules'>"
		"<params><param name='event_filter' value='ALL,DTMF,CUSTOM,bad-name'/></params>"
		"<filter mode='rules'><rule><event name='DTMF'/></rule><rule><event name='SWITCH_EVENT_DTMF'/></rule></filter>"
		"</profile></producers></configuration>";
	fst_check(integration_reload(snapshot) == SWITCH_STATUS_SUCCESS);
	fst_check(bind_calls == 1 && integration_find("rules")->event_subscriptions == 1);
	deliver(SWITCH_EVENT_DTMF, NULL);
	integration_value(NULL);
	fst_check(read_counter(&callbacks) == 1 && read_counter(&message_allocations) == 1);
	fst_check(read_counter(&serialized) == 1 && read_counter(&enqueue_calls) == 1);
}
FST_TEST_END()

FST_TEST_BEGIN(empty_rules_deny_all)
{
	fst_check(integration_profile("empty", "<filter mode='rules'/>") == SWITCH_STATUS_SUCCESS);
	fst_check(integration_find("empty")->event_subscriptions == 0 && bind_calls == 0);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&callbacks) == 0 && read_counter(&message_allocations) == 0);
	fst_check(read_counter(&serialized) == 0 && read_counter(&enqueue_calls) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(general_specific_rules_and_independent_profiles)
{
	fst_check(integration_profile("a", "<filter mode='rules'><rule><event name='ALL'/></rule><rule><event name='DTMF'/></rule></filter>") == SWITCH_STATUS_SUCCESS);
	fst_check(integration_profile("b", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
	fst_check(bind_calls == 2 && integration_find("a")->events[0].id == SWITCH_EVENT_ALL);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&callbacks) == 2 && read_counter(&serialized) == 2 && read_counter(&enqueue_calls) == 2);
}
FST_TEST_END()

FST_TEST_BEGIN(rejection_before_allocation_json_and_enqueue)
{
	fst_check(integration_profile("rules", "<filter mode='rules'><rule><event name='CUSTOM'/><condition field='Event-Subclass' op='eq' value='amqp::lifecycle'/><condition field='tenant' op='eq' value='acme'/></rule></filter>") == SWITCH_STATUS_SUCCESS);
	integration_value("other"); integration_value(NULL);
	fst_check(read_counter(&callbacks) == 2 && read_counter(&message_allocations) == 0);
	fst_check(read_counter(&serialized) == 0 && read_counter(&enqueue_calls) == 0);
	integration_value("acme");
	fst_check(read_counter(&callbacks) == 3 && read_counter(&message_allocations) == 1);
	fst_check(read_counter(&serialized) == 1 && read_counter(&enqueue_calls) == 1);
}
FST_TEST_END()

FST_TEST_BEGIN(preparation_has_no_resources_and_outlives_xml)
{
	switch_xml_t xml = switch_xml_parse_str_dynamic("<profile><params><param name='format_fields' value='#owned'/></params><connections><connection name='local'><param name='hostname' value='owned-host'/></connection></connections>" RULE_DTMF "</profile>", SWITCH_TRUE);
	mod_amqp_producer_prepared_t *prepared = NULL;
	mod_amqp_producer_profile_t *p;
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	fst_check(mod_amqp_producer_prepare("prepared", xml, &prepared) == SWITCH_STATUS_SUCCESS);
	switch_xml_free(xml);
	fst_check(queue_creations == 0 && thread_creations == 0 && hash_insertions == 0 && bind_calls == 0);
	fst_check(prepared->profile->conn_root == NULL && prepared->profile->send_queue == NULL);
	fst_check(prepared->profile->filter_engine != NULL && switch_core_hash_empty(mod_amqp_globals.producer_hash));
	fst_check(mod_amqp_producer_activate(prepared) == SWITCH_STATUS_SUCCESS);
	fst_check(prepared->profile == NULL);
	fst_check(mod_amqp_producer_activate(prepared) != SWITCH_STATUS_SUCCESS);
	mod_amqp_producer_prepared_destroy(&prepared);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	p = integration_find("prepared");
	fst_check(!strcmp(p->conn_root->hostname, "owned-host") && !strcmp(p->format_fields[0].name[0], "#owned"));
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&serialized) == 1);
}
FST_TEST_END()

FST_TEST_BEGIN(prepared_same_name_never_deletes_active_owner)
{
	switch_xml_t xml = switch_xml_parse_str_dynamic("<profile>" RULE_DTMF "</profile>", SWITCH_TRUE);
	mod_amqp_producer_prepared_t *prepared = NULL;
	mod_amqp_producer_profile_t *owner;
	fst_check(create_profile("same", "DTMF") == SWITCH_STATUS_SUCCESS);
	owner = integration_find("same");
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	fst_check(mod_amqp_producer_prepare("same", xml, &prepared) == SWITCH_STATUS_SUCCESS);
	mod_amqp_producer_prepared_destroy(&prepared);
	fst_check(integration_find("same") == owner);
	fst_check(mod_amqp_producer_prepare("same", xml, &prepared) == SWITCH_STATUS_SUCCESS);
	fst_check(mod_amqp_producer_activate(prepared) != SWITCH_STATUS_SUCCESS);
	mod_amqp_producer_prepared_destroy(&prepared);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	switch_xml_free(xml);
	fst_check(integration_find("same") == owner && read_counter(&unbind_calls) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(duplicate_and_missing_names_fail_before_switch)
{
	mod_amqp_producer_profile_t *owner;
	fst_check(create_profile("old", "DTMF") == SWITCH_STATUS_SUCCESS);
	owner = integration_find("old");
	fst_check(integration_reload("<configuration><producers>" PROFILE_NEW PROFILE_NEW "</producers></configuration>") != SWITCH_STATUS_SUCCESS);
	fst_check(integration_find("old") == owner && read_counter(&unbind_calls) == 0);
	fst_check(integration_reload("<configuration><producers>" PROFILE_NEW "<profile/></producers></configuration>") != SWITCH_STATUS_SUCCESS);
	fst_check(integration_find("old") == owner && read_counter(&unbind_calls) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(activation_failures_clean_entire_new_set)
{
	int i;
	for (i = 0; i < 4; i++) {
		fail_queue_at = i == 0 ? queue_creations + 2 : 0;
		fail_thread_at = i == 1 ? thread_creations + 2 : 0;
		fail_hash_at = i == 2 ? hash_insertions + 2 : 0;
		fail_bind_at = i == 3 ? bind_calls + 2 : 0;
		fst_check(integration_reload("<configuration><producers>" PROFILE_NEW "<profile name='second'>" RULE_DTMF "</profile></producers></configuration>") != SWITCH_STATUS_SUCCESS);
		fst_check(switch_core_hash_empty(mod_amqp_globals.producer_hash));
		fail_queue_at = fail_thread_at = fail_hash_at = fail_bind_at = 0;
	}
	fst_check(read_counter(&engines_destroyed) == 8);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&callbacks) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(retained_engine_after_unbind_and_join_failure)
{
	mod_amqp_producer_profile_t *p;
	mod_amqp_filter_engine_t *engine;
	fst_check(integration_profile("retained", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
	p = integration_find("retained"); engine = p->filter_engine;
	fail_unbind = fail_join = 1;
	fst_check(destroy_profile(&p) != SWITCH_STATUS_SUCCESS);
	fst_check(p && p->filter_engine == engine && p->event_nodes[0] && p->producer_thread);
	fst_check(read_counter(&engines_destroyed) == 0 && integration_find("retained") == p);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&serialized) == 0);
	fst_check(destroy_profile(&p) == SWITCH_STATUS_SUCCESS);
	fst_check(p == NULL && read_counter(&engines_destroyed) == 1);
}
FST_TEST_END()

FST_TEST_BEGIN(activation_failure_with_failed_cleanup_remains_reachable)
{
	mod_amqp_producer_profile_t *p;
	fail_bind_at = 2;
	persistent_unbind_failure = 1;
	fst_check(integration_reload("<configuration><producers>" PROFILE_NEW "<profile name='second'>" RULE_DTMF "</profile></producers></configuration>") != SWITCH_STATUS_SUCCESS);
	p = integration_find("new");
	fst_check(p && p->filter_engine && p->event_nodes[0]);
	fst_check(integration_find("second") == NULL && read_counter(&engines_destroyed) == 1);
	persistent_unbind_failure = 0;
	fst_check(destroy_profile(&p) == SWITCH_STATUS_SUCCESS);
	fst_check(read_counter(&engines_destroyed) == 2);
}
FST_TEST_END()

FST_TEST_BEGIN(held_callback_blocks_engine_destruction_and_reload_shutdown)
{
	switch_thread_t *delivery, *destroyer, *shutdown_thread;
	switch_status_t status, shutdown_status = SWITCH_STATUS_GENERR;
	destroy_context_t context;
	fst_check(integration_profile("held", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
	context.profile = integration_find("held");
	set_counter(&hold_callback, 1);
	switch_assert(switch_thread_create(&delivery, NULL, delivery_thread, NULL, fst_pool) == SWITCH_STATUS_SUCCESS);
	fst_check(await_counter(&callback_entered, 1));
	switch_assert(switch_thread_create(&destroyer, NULL, destroy_thread, &context, fst_pool) == SWITCH_STATUS_SUCCESS);
	fst_check(await_counter(&unbind_calls, 1));
	fst_check(read_counter(&engines_destroyed) == 0 && !read_counter(&destroy_done));
	fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
	switch_assert(switch_thread_create(&shutdown_thread, NULL, integration_shutdown_thread, &shutdown_status, fst_pool) == SWITCH_STATUS_SUCCESS);
	fst_check(await_counter(&shutdown_entered, 1));
	fst_check(!read_counter(&shutdown_done));
	set_counter(&release_callback, 1);
	switch_thread_join(&status, delivery); switch_thread_join(&status, destroyer);
	switch_thread_join(&status, shutdown_thread);
	fst_check(shutdown_status == SWITCH_STATUS_SUCCESS);
	fst_check(context.status == SWITCH_STATUS_SUCCESS && context.profile == NULL);
	fst_check(read_counter(&engines_destroyed) == 1);
}
FST_TEST_END()

FST_TEST_BEGIN(all_old_bindings_removed_before_any_new_binding)
{
	fst_check(create_profile("a", "DTMF,HEARTBEAT") == SWITCH_STATUS_SUCCESS);
	fst_check(create_profile("b", "DTMF,CUSTOM") == SWITCH_STATUS_SUCCESS);
	expected_old_unbinds = 4;
	fst_check(integration_reload(CONFIG_NEW) == SWITCH_STATUS_SUCCESS);
	fst_check(new_binding_before_old_removed == 0 && read_counter(&unbind_calls) == 4);
	fst_check(integration_find("a") == NULL && integration_find("b") == NULL && integration_find("new"));
}
FST_TEST_END()

FST_TEST_BEGIN(teardown_failure_never_activates_new_set)
{
	fst_check(integration_profile("old", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
	fail_join = 1;
	fst_check(integration_reload(CONFIG_NEW) != SWITCH_STATUS_SUCCESS);
	fst_check(bind_calls == 1 && integration_find("new") == NULL);
	fst_check(integration_find("old") && integration_find("old")->filter_engine);
	fst_check(integration_reload(CONFIG_NEW) == SWITCH_STATUS_SUCCESS);
	fst_check(bind_calls == 2 && integration_find("old") == NULL);
}
FST_TEST_END()

FST_TEST_BEGIN(management_reentrancy_command_worker_and_shutdown)
{
	mod_amqp_command_profile_t command = {0};
	fst_check(integration_profile("old", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	switch_mutex_init(&command.mutex, SWITCH_MUTEX_NESTED, fst_pool);
	command.command_thread_started = SWITCH_TRUE; command.command_thread_id = switch_thread_self();
	switch_core_hash_insert(mod_amqp_globals.command_hash, "caller", &command);
	fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
	switch_core_hash_delete(mod_amqp_globals.command_hash, "caller");
	fst_check(integration_find("old") != NULL);
	fst_check(mod_amqp_shutdown() == SWITCH_STATUS_SUCCESS);
	fst_check(mod_amqp_do_config(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS);
}
FST_TEST_END()

FST_TEST_BEGIN(logging_rebound_after_successful_reload)
{
	mod_amqp_logging_profile_t *logging;
	int iteration;
	for (iteration = 0; iteration < 2; iteration++) {
		fst_check(integration_reload("<configuration><producers>" PROFILE_NEW "</producers><logging><profile name='log'><params><param name='log-levels' value='err'/></params></profile></logging></configuration>") == SWITCH_STATUS_SUCCESS);
		logging = switch_core_hash_find(mod_amqp_globals.logging_hash, "log");
		fst_check(logging && mod_amqp_globals.logging_bound);
		/* Real Core logging dispatch under its BINDLOCK into production recv. */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "amqp-integration-log-marker\n");
		fst_check(await_counter(&logger_seen, iteration + 1));
		fst_check(switch_queue_size(logging->send_queue) > 0);
	}
}
FST_TEST_END()

FST_TEST_BEGIN(adjacent_profile_errors_reach_api)
{
	fst_check(integration_reload("<configuration><producers>" PROFILE_NEW "</producers><commands><profile/></commands><logging><profile/></logging></configuration>") != SWITCH_STATUS_SUCCESS);
	fst_check(integration_find("new") != NULL); /* Producer switch is not rolled back. */
	fst_check(mod_amqp_globals.logging_bound);
}
FST_TEST_END()

FST_TEST_BEGIN(parallel_callbacks_queue_overflow_and_breaker)
{
	switch_thread_t *threads[8];
	switch_status_t status;
	mod_amqp_producer_profile_t *p;
	int i, before;
	fst_check(integration_reload("<configuration><producers><profile name='flood'><params><param name='send_queue_size' value='1'/><param name='circuit_breaker_ms' value='60000'/></params>" RULE_DTMF "</profile></producers></configuration>") == SWITCH_STATUS_SUCCESS);
	p = integration_find("flood");
	for (i = 0; i < 8; i++) switch_assert(switch_thread_create(&threads[i], NULL, integration_flood, NULL, fst_pool) == SWITCH_STATUS_SUCCESS);
	for (i = 0; i < 8; i++) switch_thread_join(&status, threads[i]);
	fst_check(read_counter(&callbacks) == 4000 && switch_queue_size(p->send_queue) == 1);
	fst_check(read_counter(&enqueue_calls) >= 2 && read_counter(&serialized) == read_counter(&enqueue_calls));
	switch_mutex_lock(p->state_mutex);
	fst_check(p->circuit_breaker_reset_time > switch_time_now());
	switch_mutex_unlock(p->state_mutex);
	before = read_counter(&message_allocations);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&message_allocations) == before);
}
FST_TEST_END()

FST_TEST_BEGIN(sender_barrier_retains_engine)
{
	switch_thread_t *destroyer;
	switch_status_t status;
	destroy_context_t context;
	fst_check(integration_profile("held", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
	context.profile = integration_find("held");
	set_counter(&hold_sender, 1);
	switch_assert(switch_thread_create(&destroyer, NULL, destroy_thread, &context, fst_pool) == SWITCH_STATUS_SUCCESS);
	fst_check(await_counter(&sender_stopped, 1));
	fst_check(read_counter(&engines_destroyed) == 0 && !read_counter(&destroy_done));
	set_counter(&release_sender, 1);
	switch_thread_join(&status, destroyer);
	fst_check(context.status == SWITCH_STATUS_SUCCESS && read_counter(&engines_destroyed) == 1);
}
FST_TEST_END()

FST_TEST_BEGIN(maximum_unique_subscriptions_and_more_rules_than_bindings)
{
	switch_xml_t xml, filter, rule, event;
	mod_amqp_producer_prepared_t *prepared = NULL;
	mod_amqp_producer_profile_t *p;
	int i;
	xml = switch_xml_new("profile");
	filter = switch_xml_add_child_d(xml, "filter", 0);
	switch_xml_set_attr_d(filter, "mode", "rules");
	rule = switch_xml_add_child_d(filter, "rule", 0);
	for (i = 0; i < SWITCH_EVENT_ALL; i++) {
		event = switch_xml_add_child_d(rule, "event", i);
		switch_xml_set_attr_d(event, "name", switch_event_name((switch_event_types_t)i));
	}
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	fst_check(mod_amqp_producer_prepare("all-specific", xml, &prepared) == SWITCH_STATUS_SUCCESS);
	switch_xml_free(xml);
	fst_check(mod_amqp_producer_activate(prepared) == SWITCH_STATUS_SUCCESS);
	mod_amqp_producer_prepared_destroy(&prepared);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	p = integration_find("all-specific");
	fst_check(p->event_subscriptions == SWITCH_EVENT_ALL && bind_calls == SWITCH_EVENT_ALL);
	for (i = 0; i < SWITCH_EVENT_ALL; i++) fst_check(p->event_nodes[i] && p->events[i].id == i && p->events[i].subclass == NULL);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&callbacks) == 1 && read_counter(&enqueue_calls) == 1);
	fst_check(destroy_profile(&p) == SWITCH_STATUS_SUCCESS);

	xml = switch_xml_new("profile");
	filter = switch_xml_add_child_d(xml, "filter", 0);
	switch_xml_set_attr_d(filter, "mode", "rules");
	for (i = 0; i < (int)MOD_AMQP_FILTER_MAX_RULES; i++) {
		rule = switch_xml_add_child_d(filter, "rule", i);
		event = switch_xml_add_child_d(rule, "event", 0);
		switch_xml_set_attr_d(event, "name", "DTMF");
	}
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	fst_check(mod_amqp_producer_prepare("many", xml, &prepared) == SWITCH_STATUS_SUCCESS);
	switch_xml_free(xml);
	fst_check(mod_amqp_producer_activate(prepared) == SWITCH_STATUS_SUCCESS);
	mod_amqp_producer_prepared_destroy(&prepared);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	fst_check(integration_find("many")->event_subscriptions == 1);
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&callbacks) == 2 && read_counter(&enqueue_calls) == 2);
}
FST_TEST_END()

FST_TEST_BEGIN(partial_rules_bindings_fail_at_each_position)
{
	int i;
	for (i = 1; i <= 3; i++) {
		bind_calls = 0; fail_bind_at = i;
		set_counter(&unbind_calls, 0);
		fst_check(integration_profile("partial", "<filter mode='rules'><rule><event name='DTMF'/><event name='HEARTBEAT'/><event name='CUSTOM'/></rule></filter>") != SWITCH_STATUS_SUCCESS);
		fst_check(read_counter(&unbind_calls) == i - 1 && integration_find("partial") == NULL);
		fst_check(read_counter(&engines_destroyed) == i);
	}
	deliver(SWITCH_EVENT_DTMF, NULL);
	fst_check(read_counter(&callbacks) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(invalid_connection_preparation_preserves_old_set)
{
	mod_amqp_producer_profile_t *old;
	fst_check(create_profile("old", "DTMF") == SWITCH_STATUS_SUCCESS);
	old = integration_find("old");
	fst_check(integration_reload("<configuration><producers>" PROFILE_NEW "<profile name='late'><connections><connection/></connections>" RULE_DTMF "</profile></producers></configuration>") != SWITCH_STATUS_SUCCESS);
	fst_check(integration_find("old") == old && read_counter(&unbind_calls) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(adjacent_creation_and_join_failures_reach_api)
{
	const char *commands = "<configuration><commands><profile name='command'/></commands></configuration>";
	const char *logging = "<configuration><logging><profile name='log'/></logging></configuration>";
	fail_other_thread = 1;
	fst_check(integration_reload(commands) != SWITCH_STATUS_SUCCESS);
	fst_check(switch_core_hash_empty(mod_amqp_globals.command_hash));
	fst_check(integration_reload(logging) != SWITCH_STATUS_SUCCESS);
	fst_check(switch_core_hash_empty(mod_amqp_globals.logging_hash));
	fail_other_thread = 0;
	fst_check(integration_reload(commands) == SWITCH_STATUS_SUCCESS);
	fst_check(switch_core_hash_find(mod_amqp_globals.command_hash, "command") != NULL);
	fail_join = 1;
	fst_check(integration_reload("<configuration/>") != SWITCH_STATUS_SUCCESS);
	fst_check(switch_core_hash_find(mod_amqp_globals.command_hash, "command") != NULL);
	fst_check(integration_reload("<configuration/>") == SWITCH_STATUS_SUCCESS);
	fst_check(integration_reload(logging) == SWITCH_STATUS_SUCCESS);
	fail_join = 1;
	fst_check(integration_reload("<configuration/>") != SWITCH_STATUS_SUCCESS);
	fst_check(switch_core_hash_find(mod_amqp_globals.logging_hash, "log") != NULL);
	fst_check(mod_amqp_globals.logging_bound);
	fst_check(integration_reload("<configuration/>") == SWITCH_STATUS_SUCCESS);
}
FST_TEST_END()

FST_TEST_BEGIN(invalid_network_timeout_preserves_active_producers)
{
    const char *values[] = {"0", "-1", "60001", "not-a-number", "999999999999999999999999", NULL};
    char snapshot[2048];
    mod_amqp_producer_profile_t *old;
    int i;
    fst_check(integration_profile("old", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
    old = integration_find("old");
    for (i = 0; values[i]; i++) {
        switch_snprintf(snapshot, sizeof(snapshot),
            "<configuration><producers><profile name='new'><connections><connection name='net'>"
            "<param name='connect-timeout-ms' value='%s'/></connection></connections>"
            RULE_DTMF "</profile></producers></configuration>", values[i]);
        fst_check(integration_reload(snapshot) != SWITCH_STATUS_SUCCESS);
        fst_check(integration_find("old") == old && read_counter(&unbind_calls) == 0);
    }
}
FST_TEST_END()

FST_TEST_BEGIN(shutdown_error_does_not_leave_other_workers_running)
{
    switch_hash_index_t *hi;
    mod_amqp_producer_profile_t *retained;
    fst_check(integration_reload("<configuration><producers>" PROFILE_NEW
        "<profile name='other'>" RULE_DTMF "</profile></producers>"
        "<logging><profile name='log'/></logging></configuration>") == SWITCH_STATUS_SUCCESS);
    fail_unbind = 1;
    fst_check(mod_amqp_shutdown() == SWITCH_STATUS_NOUNLOAD);
    fst_check(mod_amqp_globals.health == MOD_AMQP_HEALTH_RESTART_REQUIRED);
    fst_check(switch_core_hash_empty(mod_amqp_globals.logging_hash));
    fst_check(!mod_amqp_globals.logging_bound && read_counter(&engines_destroyed) == 1);
    hi = switch_core_hash_first(mod_amqp_globals.producer_hash);
    fst_check(hi != NULL);
    switch_core_hash_this(hi, NULL, NULL, (void **)&retained);
    switch_safe_free(hi);
    fst_check(!mod_amqp_producer_is_running(retained) && !retained->producer_thread);
    fst_check(mod_amqp_shutdown() == SWITCH_STATUS_SUCCESS);
    fst_check(read_counter(&engines_destroyed) == 2);
}
FST_TEST_END()

FST_TEST_BEGIN(routing_key_empty_missing_and_encoded_boundaries)
{
    mod_amqp_producer_profile_t profile = {0};
    switch_event_t *event = NULL;
    char key[MAX_AMQP_ROUTING_KEY_LENGTH + 1], value[257];
    switch_assert(switch_event_create(&event, SWITCH_EVENT_DTMF) == SWITCH_STATUS_SUCCESS);
    memset(key, 0xbe, sizeof(key));
    fst_check(mod_amqp_producer_routing_key(&profile, key, event, profile.format_fields) == SWITCH_STATUS_SUCCESS);
    fst_check_string_equals(key, "");
    profile.format_fields[0].size = 1;
    profile.format_fields[0].name[0] = "missing";
    memset(key, 0xbe, sizeof(key));
    fst_check(mod_amqp_producer_routing_key(&profile, key, event, profile.format_fields) == SWITCH_STATUS_SUCCESS);
    fst_check_string_equals(key, "");
    profile.format_fields[0].name[0] = "route";
    memset(value, '.', 85); value[85] = '\0';
    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "route", value);
    fst_check(mod_amqp_producer_routing_key(&profile, key, event, profile.format_fields) == SWITCH_STATUS_SUCCESS);
    fst_check(strlen(key) == 255 && key[255] == '\0' && !memcmp(key, "%2E", 3));
    switch_event_del_header(event, "route");
    value[85] = '.'; value[86] = '\0';
    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "route", value);
    fst_check(mod_amqp_producer_routing_key(&profile, key, event, profile.format_fields) != SWITCH_STATUS_SUCCESS);
    fst_check_string_equals(key, "");
    switch_event_del_header(event, "route");
    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "route", "a b.\xc3\xa9");
    fst_check(mod_amqp_producer_routing_key(&profile, key, event, profile.format_fields) == SWITCH_STATUS_SUCCESS);
    fst_check_string_equals(key, "a+b%2E%C3%A9");
    switch_event_destroy(&event);
}
FST_TEST_END()

FST_TEST_BEGIN(oversized_routing_key_is_dropped_before_json)
{
    mod_amqp_producer_profile_t *profile;
    switch_event_t *event = NULL;
    char literal[258];
    fst_check(integration_profile("route", RULE_DTMF) == SWITCH_STATUS_SUCCESS);
    profile = integration_find("route");
    memset(literal, 'x', sizeof(literal)); literal[0] = '#'; literal[257] = '\0';
    profile->format_fields[0].name[0] = literal;
    switch_assert(switch_event_create(&event, SWITCH_EVENT_DTMF) == SWITCH_STATUS_SUCCESS);
    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "AMQP-Lifecycle-Test", "true");
    switch_event_deliver(&event);
    fst_check(read_counter(&message_allocations) == 1 && read_counter(&serialized) == 0 && read_counter(&enqueue_calls) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(logging_queue_overflow_releases_rejected_message)
{
    mod_amqp_logging_profile_t *logging;
    fst_check(integration_reload("<configuration><logging><profile name='bounded'><params>"
        "<param name='send_queue_size' value='1'/><param name='log-levels' value='err'/>"
        "</params></profile></logging></configuration>") == SWITCH_STATUS_SUCCESS);
    logging = switch_core_hash_find(mod_amqp_globals.logging_hash, "bounded");
    fst_check(logging != NULL);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "amqp-integration-log-marker overflow 1\n");
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "amqp-integration-log-marker overflow 2\n");
    fst_check(await_counter(&logger_seen, 2));
    fst_check(switch_queue_size(logging->send_queue) == 1);
    /* LSan checks the rejected JSON/message after the fixture drains the queue. */
}
FST_TEST_END()
