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

FST_TEST_BEGIN(api_profiles_snapshot_and_unknown_command_are_read_only)
{
    char reply[4096] = {0};
    cJSON *json, *profile;
    fst_check(integration_reload(CONFIG_NEW) == SWITCH_STATUS_SUCCESS);
    deliver(SWITCH_EVENT_DTMF, NULL);
    fst_check(api_reply_request_command("api amqp profiles\n\n", reply, sizeof(reply)) == 0);
    fst_check(strstr(reply, "+OK mod_amqp profiles\n") == reply);
    json = cJSON_Parse(strchr(reply, '\n') + 1);
    fst_check(json != NULL);
    profile = cJSON_GetArrayItem(cJSON_GetObjectItem(json, "producers"), 0);
    fst_check(profile != NULL);
    fst_check_string_equals(cJSON_GetObjectItem(profile, "name")->valuestring, "new");
    fst_check(cJSON_GetObjectItem(profile, "queue_depth")->valueint == 1);
    fst_check_string_equals(cJSON_GetObjectItem(profile, "enqueued")->valuestring, "1");
    fst_check_string_equals(cJSON_GetObjectItem(profile, "publish_ok")->valuestring, "0");
    fst_check(cJSON_GetObjectItem(profile, "enabled")->valueint == 1);
    cJSON_Delete(json);
    config_snapshot = "<configuration/>";
    fst_check(api_reply_request_command("api amqp profiels\n\n", reply, sizeof(reply)) == 0);
    fst_check(strstr(reply, "-ERR usage:") == reply);
    fst_check(integration_find("new") != NULL && read_counter(&unbind_calls) == 0);
}
FST_TEST_END()

FST_TEST_BEGIN(api_profiles_busy_does_not_block_status)
{
    char reply[4096] = {0};
    int result;
    switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
    result = api_reply_request_command("api amqp profiles\n\n", reply, sizeof(reply));
    switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
    fst_check(result == 0);
    fst_check_string_equals(reply, "-ERR mod_amqp profile snapshot busy\n");
    switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
    result = api_reply_request_command("api amqp status\n\n", reply, sizeof(reply));
    switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
    fst_check(result == 0 && strstr(reply, "state=ACTIVE") != NULL);
}
FST_TEST_END()

FST_TEST_BEGIN(api_profiles_retained_owner_and_uint64_precision)
{
    char reply[4096] = {0};
    cJSON *json, *profile;
    mod_amqp_producer_profile_t *owner;
    fst_check(integration_reload(CONFIG_NEW) == SWITCH_STATUS_SUCCESS);
    owner = integration_find("new");
    switch_mutex_lock(owner->state_mutex);
    owner->io.counters[MOD_AMQP_PUBLISH_OK] = UINT64_MAX;
    switch_mutex_unlock(owner->state_mutex);
    fail_unbind = 1;
    fst_check(destroy_profile(&owner) != SWITCH_STATUS_SUCCESS);
    fst_check(api_reply_request_command("api amqp profiles\n\n", reply, sizeof(reply)) == 0);
    json = cJSON_Parse(strchr(reply, '\n') + 1);
    fst_check(json != NULL);
    profile = cJSON_GetArrayItem(cJSON_GetObjectItem(json, "producers"), 0);
    fst_check(profile != NULL && cJSON_GetObjectItem(profile, "retained")->valueint == 1);
    fst_check(cJSON_GetObjectItem(profile, "enabled")->valueint == 0);
    fst_check(cJSON_GetObjectItem(profile, "join_pending")->valueint == 0);
    fst_check_string_equals(cJSON_GetObjectItem(profile, "connection")->valuestring, "stopped");
    fst_check_string_equals(cJSON_GetObjectItem(profile, "publish_ok")->valuestring, "18446744073709551615");
    cJSON_Delete(json);
}
FST_TEST_END()
