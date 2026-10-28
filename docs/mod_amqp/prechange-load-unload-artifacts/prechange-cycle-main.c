/* Isolated load/unload check for the unmodified mod_amqp from develop. */
#include <switch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int api_present(void)
{
	switch_api_interface_t *api = switch_loadable_module_get_api_interface("amqp");
	int present = api != NULL;
	if (api) UNPROTECT_INTERFACE(api);
	return present;
}

static int deliver_dtmf(void)
{
	switch_event_t *event = NULL;
	if (switch_event_create(&event, SWITCH_EVENT_DTMF) != SWITCH_STATUS_SUCCESS) return 0;
	switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Probe-Origin", "develop");
	switch_event_deliver(&event);
	return 1;
}

int main(int argc, char **argv)
{
	const char *err = NULL;
	int cycle;
	switch_bool_t force = argc > 1 && !strcmp(argv[1], "force") ? SWITCH_TRUE : SWITCH_FALSE;
	SWITCH_GLOBAL_dirs.mod_dir = strdup(AMQP_PROBE_FIXTURE_ROOT "/conf");
	SWITCH_GLOBAL_dirs.conf_dir = strdup(AMQP_PROBE_FIXTURE_ROOT "/conf");
	SWITCH_GLOBAL_dirs.log_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.run_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.db_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.data_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
	switch_core_set_globals();
	if (switch_core_init_and_modload(SCF_LOG_DISABLE, SWITCH_TRUE, &err) != SWITCH_STATUS_SUCCESS) return 10;
	for (cycle = 0; cycle < 3; cycle++) {
		switch_status_t load = switch_loadable_module_load_module(AMQP_PROBE_MODULE_DIR, "mod_amqp", SWITCH_FALSE, &err);
		switch_status_t reload;
		switch_status_t unload;
		switch_stream_handle_t stream = {0};
		if (load != SWITCH_STATUS_SUCCESS || !api_present() || !deliver_dtmf()) return 11;
		SWITCH_STANDARD_STREAM(stream);
		reload = switch_api_execute("amqp", NULL, NULL, &stream);
		printf("cycle=%d load=%d reload=%d reload_text=%s\n", cycle, (int)load, (int)reload,
			stream.data ? (char *)stream.data : "<empty>");
		switch_safe_free(stream.data);
		if (reload != SWITCH_STATUS_SUCCESS) return 12;
		unload = switch_loadable_module_unload_module(NULL, "mod_amqp", force, &err);
		printf("cycle=%d force=%d unload=%d exists=%d api=%d\n", cycle, (int)force, (int)unload,
			(int)switch_loadable_module_exists("mod_amqp"), api_present());
		if (unload != SWITCH_STATUS_SUCCESS ||
			switch_loadable_module_exists("mod_amqp") == SWITCH_STATUS_SUCCESS ||
			api_present() || !deliver_dtmf()) return 13;
	}
	return switch_core_destroy() == SWITCH_STATUS_SUCCESS ? 0 : 14;
}
