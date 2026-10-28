/* Isolated ASan control: same FreeSWITCH Core/APR thread setup, no mod_amqp. */
#include <switch.h>
#include <stdio.h>

static switch_mutex_t *control_mutex;
static switch_thread_cond_t *control_cond;
static int control_release;

static void *SWITCH_THREAD_FUNC worker(switch_thread_t *thread, void *data)
{
	(void)data;
	switch_mutex_lock(control_mutex);
	while (!control_release) switch_thread_cond_wait(control_cond, control_mutex);
	switch_mutex_unlock(control_mutex);
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

int main(int argc, char **argv)
{
	switch_memory_pool_t *pool = NULL;
	switch_threadattr_t *attr = NULL;
	switch_thread_t *thread = NULL;
	switch_status_t result;
	const char *error = NULL;
	int i;
	SWITCH_GLOBAL_dirs.mod_dir = strdup(AMQP_REPRO_ROOT "/conf");
	SWITCH_GLOBAL_dirs.conf_dir = strdup(AMQP_REPRO_ROOT "/../../../src/mod/event_handlers/mod_amqp/test/conf");
	SWITCH_GLOBAL_dirs.log_dir = strdup(AMQP_REPRO_ROOT);
	SWITCH_GLOBAL_dirs.run_dir = strdup(AMQP_REPRO_ROOT);
	SWITCH_GLOBAL_dirs.db_dir = strdup(AMQP_REPRO_ROOT);
	SWITCH_GLOBAL_dirs.data_dir = strdup(AMQP_REPRO_ROOT);
	switch_core_set_globals();
	if (switch_core_init_and_modload(SCF_LOG_DISABLE, SWITCH_TRUE, &error) != SWITCH_STATUS_SUCCESS) return 10;
	fprintf(stderr, "core initialized\n");
	if (argc > 1 && switch_loadable_module_load_module(argv[1],
		"mod_amqp_api_reply_proxy", SWITCH_FALSE, &error) != SWITCH_STATUS_SUCCESS) return 18;
	if (argc > 2 && switch_loadable_module_load_module(argv[2],
		"mod_event_socket", SWITCH_TRUE, &error) != SWITCH_STATUS_SUCCESS) return 19;
	if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) return 11;
	if (switch_mutex_init(&control_mutex, SWITCH_MUTEX_UNNESTED, pool) != SWITCH_STATUS_SUCCESS) return 20;
	if (switch_thread_cond_create(&control_cond, pool) != SWITCH_STATUS_SUCCESS) return 21;
	if (switch_threadattr_create(&attr, pool) != SWITCH_STATUS_SUCCESS) return 12;
	if (switch_threadattr_stacksize_set(attr, SWITCH_THREAD_STACKSIZE) != SWITCH_STATUS_SUCCESS) return 13;
	if (switch_threadattr_detach_set(attr, 0) != SWITCH_STATUS_SUCCESS) return 14;
	for (i = 0; i < 100; i++) {
		fprintf(stderr, "iteration %d\n", i);
		control_release = 0;
		if (switch_thread_create(&thread, attr, worker, NULL, pool) != SWITCH_STATUS_SUCCESS) return 15;
		switch_mutex_lock(control_mutex);
		control_release = 1;
		switch_thread_cond_broadcast(control_cond);
		switch_mutex_unlock(control_mutex);
		if (switch_thread_join(&result, thread) != SWITCH_STATUS_SUCCESS) return 16;
	}
	switch_core_destroy_memory_pool(&pool);
	fprintf(stderr, "workers joined\n");
	return switch_core_destroy() == SWITCH_STATUS_SUCCESS ? 0 : 17;
}
