/* These tests use the real mod_event_socket listener and switch_api_execute(). */
FST_TEST_BEGIN(api_reply_success_over_esl)
{
	char reply[128] = { 0 };
	config_snapshot = CONFIG_NEW;
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "+OK mod_amqp configuration reloaded\n");
	fst_check(integration_find("new") != NULL);
}
FST_TEST_END()

FST_TEST_BEGIN(api_reply_invalid_mode_over_esl)
{
	char reply[128] = { 0 };
	mod_amqp_producer_profile_t *old;
	fst_check(create_profile("old", "DTMF") == SWITCH_STATUS_SUCCESS);
	old = integration_find("old");
	config_snapshot = "<configuration><producers>" PROFILE_NEW
		"<profile name='invalid'><filter mode='wrong'/></profile></producers></configuration>";
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "-ERR mod_amqp configuration reload failed\n");
	fst_check(integration_find("old") == old && read_counter(&unbind_calls) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(api_reply_busy_lifecycle_mutex_over_esl)
{
	char reply[128] = { 0 };
	config_snapshot = CONFIG_NEW;
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	/* ESL worker is a different thread: trylock must reject the reload. */
	{
		int result = api_reply_request(reply, sizeof(reply));
		switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
		fst_check(result == 0);
	}
	fst_check_string_equals(reply, "-ERR mod_amqp configuration reload failed\n");
	fst_check(integration_find("new") == NULL);
}
FST_TEST_END()

FST_TEST_BEGIN(api_reply_teardown_error_over_esl)
{
	char reply[128] = { 0 };
	mod_amqp_producer_profile_t *old;
	fst_check(create_profile("old", "DTMF") == SWITCH_STATUS_SUCCESS);
	old = integration_find("old");
	config_snapshot = CONFIG_NEW;
	fail_unbind = 1;
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "-ERR mod_amqp configuration reload failed\n");
	fst_check(integration_find("old") == old && integration_find("new") == NULL);
}
FST_TEST_END()

FST_TEST_BEGIN(api_reply_activation_error_over_esl)
{
	char reply[128] = { 0 };
	config_snapshot = "<configuration><producers>" PROFILE_NEW
		"<profile name='second'>" RULE_DTMF "</profile></producers></configuration>";
	fail_queue_at = queue_creations + 2;
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "-ERR mod_amqp configuration reload failed\n");
	fst_check(switch_core_hash_empty(mod_amqp_globals.producer_hash));
}
FST_TEST_END()
