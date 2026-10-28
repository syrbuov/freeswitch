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

FST_TEST_BEGIN(api_status_preserves_active_after_preparation_error)
{
	char reply[256] = {0};
	config_snapshot = CONFIG_NEW;
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "+OK mod_amqp configuration reloaded\n");
	config_snapshot = "<configuration><producers><profile name='bad'><filter mode='wrong'/></profile></producers></configuration>";
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "-ERR mod_amqp configuration reload failed\n");
	fst_check(api_reply_request_command("api amqp status\n\n", reply, sizeof(reply)) == 0);
	fst_check(strstr(reply, "state=ACTIVE restart_required=false") != NULL);
	fst_check(integration_find("new") != NULL);
}
FST_TEST_END()

FST_TEST_BEGIN(api_status_degraded_then_recovered)
{
	char reply[256] = {0};
	config_snapshot = "<configuration><producers>" PROFILE_NEW
		"<profile name='second'>" RULE_DTMF "</profile></producers></configuration>";
	fail_queue_at = queue_creations + 2;
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "-ERR mod_amqp configuration reload failed\n");
	fst_check(api_reply_request_command("api amqp status\n\n", reply, sizeof(reply)) == 0);
	fst_check(strstr(reply, "state=DEGRADED restart_required=false") != NULL);
	fail_queue_at = 0;
	config_snapshot = CONFIG_NEW;
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "+OK mod_amqp configuration reloaded\n");
	fst_check(api_reply_request_command("api amqp status\n\n", reply, sizeof(reply)) == 0);
	fst_check(strstr(reply, "state=ACTIVE restart_required=false") != NULL);
}
FST_TEST_END()

FST_TEST_BEGIN(api_status_available_when_restart_required)
{
	char reply[256] = {0};
	mod_amqp_health_set(MOD_AMQP_HEALTH_RESTART_REQUIRED, "test retained owner; process restart required");
	mod_amqp_globals.shutting_down = SWITCH_TRUE;
	fst_check(api_reply_request_command("api amqp status\n\n", reply, sizeof(reply)) == 0);
	fst_check(strstr(reply, "state=RESTART_REQUIRED restart_required=true") != NULL);
	fst_check(api_reply_request(reply, sizeof(reply)) == 0);
	fst_check_string_equals(reply, "-ERR mod_amqp configuration reload failed\n");
	mod_amqp_globals.shutting_down = SWITCH_FALSE;
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
