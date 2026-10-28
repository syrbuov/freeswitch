/* Isolated partial-profile-creation and optional real event-delivery check. */
#include <switch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int counter(const char *name)
{
	void *symbol = dlsym(RTLD_DEFAULT, name);
	int (*fn)(void);
	if (!symbol) return -1;
	memcpy(&fn, &symbol, sizeof(fn));
	return fn();
}

int main(int argc, char **argv)
{
	const char *err = NULL;
	switch_status_t load, unload;
	int deliver = argc > 1 && !strcmp(argv[1], "deliver");
	SWITCH_GLOBAL_dirs.mod_dir = strdup(AMQP_PROBE_FIXTURE_ROOT "/conf");
	SWITCH_GLOBAL_dirs.conf_dir = strdup(AMQP_PROBE_FIXTURE_ROOT "/conf");
	SWITCH_GLOBAL_dirs.log_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.run_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.db_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.data_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	switch_core_set_globals();
	if (switch_core_init_and_modload(SCF_LOG_DISABLE, SWITCH_TRUE, &err) != SWITCH_STATUS_SUCCESS) return 10;
	load = switch_loadable_module_load_module(AMQP_PROBE_MODULE_DIR, "mod_amqp", SWITCH_FALSE, &err);
	printf("load=%d exists=%d binds=%d individual_unbinds=%d global_unbinds=%d\n",
		(int)load, (int)switch_loadable_module_exists("mod_amqp"),
		counter("probe_binds"), counter("probe_individual_unbinds"), counter("probe_global_unbinds"));
	if (load != SWITCH_STATUS_SUCCESS || counter("probe_binds") != 2 ||
		counter("probe_individual_unbinds") != 0 || counter("probe_global_unbinds") != 0) return 11;
	if (deliver) {
		switch_event_t *event = NULL;
		if (switch_event_create(&event, SWITCH_EVENT_DTMF) != SWITCH_STATUS_SUCCESS) return 14;
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Probe-Origin", "develop-fault");
		puts("delivering DTMF to binding whose profile pool was destroyed");
		fflush(stdout);
		switch_event_deliver(&event);
		printf("delivery_returned=1 serialized_probe_events=%d\n", counter("probe_serialized_events"));
		fflush(stdout);
	}
	unload = switch_loadable_module_unload_module(NULL, "mod_amqp", SWITCH_FALSE, &err);
	printf("unload=%d exists=%d individual_unbinds=%d global_unbinds=%d\n",
		(int)unload, (int)switch_loadable_module_exists("mod_amqp"),
		counter("probe_individual_unbinds"), counter("probe_global_unbinds"));
	if (unload != SWITCH_STATUS_SUCCESS || counter("probe_global_unbinds") != 1) return 12;
	/* The Core shutdown path is checked separately; this probe verifies only
	 * the module's partial-creation ownership before process exit. */
	return 0;
}
