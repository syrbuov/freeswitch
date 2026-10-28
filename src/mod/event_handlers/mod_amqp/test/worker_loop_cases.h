/* The real production worker entry points are used in every case below. */
FST_TEST_BEGIN(command_and_logging_stop_during_blocked_open)
{
	int command;
	for (command = 0; command <= 1; command++) {
		worker_destroy_context_t context = {0};
		switch_thread_t *destroyer = NULL;
		switch_threadattr_t *attr = NULL;
		switch_status_t joined;
		worker_mode = WORKER_IO_BLOCK;
		set_counter(&destroy_done, 0);
		set_counter(&worker_io_entered, 0);
		set_counter(&worker_release_io, 0);
		fst_check(worker_create_profile(command ? SWITCH_TRUE : SWITCH_FALSE) == SWITCH_STATUS_SUCCESS);
		context.command = command ? SWITCH_TRUE : SWITCH_FALSE;
		context.profile = switch_core_hash_find(command ? mod_amqp_globals.command_hash :
			mod_amqp_globals.logging_hash, "worker");
		fst_check(context.profile && await_counter(&worker_io_entered, 1));
		fst_check(worker_state_mutex_available(&context));
		fst_check(switch_mutex_trylock(mod_amqp_globals.lifecycle_mutex) == SWITCH_STATUS_SUCCESS);
		switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
		fst_check(switch_threadattr_create(&attr, fst_pool) == SWITCH_STATUS_SUCCESS);
		fst_check(switch_thread_create(&destroyer, attr, worker_destroy_thread, &context, fst_pool) == SWITCH_STATUS_SUCCESS);
		fst_check(worker_stop_seen(&context));
		fst_check(read_counter(&destroy_done) == 0);
		set_counter(&worker_release_io, 1);
		fst_check(switch_thread_join(&joined, destroyer) == SWITCH_STATUS_SUCCESS);
		fst_check(context.status == SWITCH_STATUS_SUCCESS && context.profile == NULL);
		fst_check(switch_core_hash_empty(command ? mod_amqp_globals.command_hash : mod_amqp_globals.logging_hash));
		worker_mode = WORKER_IDLE;
	}
}
FST_TEST_END()

FST_TEST_BEGIN(worker_mutex_init_failure_cleans_partial_profile)
{
	fail_adjacent_mutex = 1;
	fst_check(worker_create_profile(SWITCH_TRUE) == SWITCH_STATUS_GENERR);
	fst_check(worker_create_profile(SWITCH_FALSE) == SWITCH_STATUS_GENERR);
	fst_check(switch_core_hash_empty(mod_amqp_globals.command_hash));
	fst_check(switch_core_hash_empty(mod_amqp_globals.logging_hash));
	fail_adjacent_mutex = 0;
}
FST_TEST_END()

FST_TEST_BEGIN(command_and_logging_stop_during_reconnect_wait)
{
	int command;
	for (command = 0; command <= 1; command++) {
		worker_destroy_context_t context = {0};
		switch_thread_t *destroyer = NULL;
		switch_threadattr_t *attr = NULL;
		switch_status_t joined;
		worker_mode = WORKER_SLEEP_BLOCK;
		set_counter(&destroy_done, 0);
		set_counter(&worker_sleep_entered, 0);
		set_counter(&worker_release_sleep, 0);
		fst_check(worker_create_profile(command ? SWITCH_TRUE : SWITCH_FALSE) == SWITCH_STATUS_SUCCESS);
		context.command = command ? SWITCH_TRUE : SWITCH_FALSE;
		context.profile = switch_core_hash_find(command ? mod_amqp_globals.command_hash :
			mod_amqp_globals.logging_hash, "worker");
		fst_check(context.profile && await_counter(&worker_sleep_entered, 1));
		fst_check(worker_state_mutex_available(&context));
		fst_check(switch_threadattr_create(&attr, fst_pool) == SWITCH_STATUS_SUCCESS);
		fst_check(switch_thread_create(&destroyer, attr, worker_destroy_thread, &context, fst_pool) == SWITCH_STATUS_SUCCESS);
		/* Logging uses a real condition wait: stop must wake it without the
		 * synthetic release required by the old command sleep wrapper. */
		if (command) {
			fst_check(worker_stop_seen(&context));
			fst_check(read_counter(&destroy_done) == 0);
		}
		set_counter(&worker_release_sleep, 1);
		fst_check(await_counter(&destroy_done, 1));
		fst_check(switch_thread_join(&joined, destroyer) == SWITCH_STATUS_SUCCESS);
		fst_check(context.status == SWITCH_STATUS_SUCCESS && context.profile == NULL);
		worker_mode = WORKER_IDLE;
	}
}
FST_TEST_END()

FST_TEST_BEGIN(logging_stop_during_queue_wait)
{
	worker_destroy_context_t context = {0};
	switch_thread_t *destroyer = NULL;
	switch_threadattr_t *attr = NULL;
	switch_status_t joined;
	worker_mode = WORKER_QUEUE_WAIT;
	set_counter(&destroy_done, 0);
	set_counter(&worker_queue_entered, 0);
	set_counter(&worker_release_queue, 0);
	fst_check(worker_create_profile(SWITCH_FALSE) == SWITCH_STATUS_SUCCESS);
	context.profile = switch_core_hash_find(mod_amqp_globals.logging_hash, "worker");
	fst_check(context.profile && await_counter(&worker_queue_entered, 1));
	fst_check(worker_state_mutex_available(&context));
	fst_check(switch_threadattr_create(&attr, fst_pool) == SWITCH_STATUS_SUCCESS);
	fst_check(switch_thread_create(&destroyer, attr, worker_destroy_thread, &context, fst_pool) == SWITCH_STATUS_SUCCESS);
	fst_check(worker_stop_seen(&context));
	fst_check(read_counter(&destroy_done) == 0);
	set_counter(&worker_release_queue, 1);
	fst_check(switch_thread_join(&joined, destroyer) == SWITCH_STATUS_SUCCESS);
	fst_check(context.status == SWITCH_STATUS_SUCCESS && context.profile == NULL);
	worker_mode = WORKER_IDLE;
}
FST_TEST_END()

FST_TEST_BEGIN(worker_failed_join_retains_owner_for_retry)
{
	int command;
	for (command = 0; command <= 1; command++) {
		worker_destroy_context_t context = {0};
		worker_mode = WORKER_IO_BLOCK;
		set_counter(&worker_io_entered, 0);
		set_counter(&worker_release_io, 0);
		fst_check(worker_create_profile(command ? SWITCH_TRUE : SWITCH_FALSE) == SWITCH_STATUS_SUCCESS);
		context.command = command ? SWITCH_TRUE : SWITCH_FALSE;
		context.profile = switch_core_hash_find(command ? mod_amqp_globals.command_hash :
			mod_amqp_globals.logging_hash, "worker");
		fst_check(context.profile && await_counter(&worker_io_entered, 1));
		fail_join = 1;
		if (command) {
			mod_amqp_command_profile_t *profile = context.profile;
			fst_check(mod_amqp_command_destroy(&profile) == SWITCH_STATUS_GENERR);
			fst_check(profile == context.profile);
		} else {
			mod_amqp_logging_profile_t *profile = context.profile;
			fst_check(mod_amqp_logging_destroy(&profile) == SWITCH_STATUS_GENERR);
			fst_check(profile == context.profile);
		}
		fst_check(switch_core_hash_find(command ? mod_amqp_globals.command_hash :
			mod_amqp_globals.logging_hash, "worker") == context.profile);
		set_counter(&worker_release_io, 1);
		if (command) {
			mod_amqp_command_profile_t *profile = context.profile;
			fst_check(mod_amqp_command_destroy(&profile) == SWITCH_STATUS_SUCCESS && profile == NULL);
		} else {
			mod_amqp_logging_profile_t *profile = context.profile;
			fst_check(mod_amqp_logging_destroy(&profile) == SWITCH_STATUS_SUCCESS && profile == NULL);
		}
		fst_check(switch_core_hash_empty(command ? mod_amqp_globals.command_hash : mod_amqp_globals.logging_hash));
		worker_mode = WORKER_IDLE;
	}
}
FST_TEST_END()
