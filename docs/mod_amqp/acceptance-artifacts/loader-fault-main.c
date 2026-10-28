/* Isolated loader contract probe. Exit 0 means the permanent policy held.
 * Core teardown is deliberately excluded until its permanent-module lifetime
 * contract has a safe, tested implementation. */
#include <switch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static void *interposer_symbol(const char *name)
{
	void *symbol = dlsym(RTLD_DEFAULT, name);
	if (!symbol) fprintf(stderr, "missing interposer symbol: %s\n", name);
	return symbol;
}

static int api_reply(const char *command, const char *arg, char *reply, size_t size)
{
	switch_stream_handle_t stream = {0};
	switch_status_t status;
	SWITCH_STANDARD_STREAM(stream);
	status = switch_api_execute(command, arg, NULL, &stream);
	if (stream.data) switch_snprintf(reply, size, "%s", (char *)stream.data);
	else reply[0] = '\0';
	switch_safe_free(stream.data);
	return (int)status;
}

int main(int argc, char **argv)
{
	const char *err = NULL;
	const char *scenario = argc > 1 ? argv[1] : "normal";
	void *symbol, *module_handle;
	void (*fail_all_unbinds)(void), (*fail_amqp_bind_at)(int);
	int (*failed_unbinds)(void), (*bind_calls)(void), (*deliveries)(void);
	int bindings_before;
	char status_text[512] = {0}, reload_text[512] = {0};
	switch_status_t load_status, unload_status, force_status, repeat_status, exists_status;
	int initial_clean = !strcmp(scenario, "initial-clean");
	int initial_retained = !strcmp(scenario, "initial-retained");
	int rc = 0;

	if (strcmp(scenario, "normal") && !initial_clean && !initial_retained) return 2;
	SWITCH_GLOBAL_dirs.mod_dir = strdup(AMQP_ACCEPTANCE_FIXTURE_ROOT "/conf");
	SWITCH_GLOBAL_dirs.conf_dir = strdup(AMQP_ACCEPTANCE_FIXTURE_ROOT "/conf");
	SWITCH_GLOBAL_dirs.log_dir = strdup(AMQP_ACCEPTANCE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.run_dir = strdup(AMQP_ACCEPTANCE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.db_dir = strdup(AMQP_ACCEPTANCE_FIXTURE_ROOT);
	SWITCH_GLOBAL_dirs.data_dir = strdup(AMQP_ACCEPTANCE_FIXTURE_ROOT);
	switch_core_set_globals();
	if (switch_core_init_and_modload(SCF_LOG_DISABLE, SWITCH_TRUE, &err) != SWITCH_STATUS_SUCCESS) return 10;
	symbol = interposer_symbol("amqp_acceptance_fail_all_unbinds");
	if (!symbol || sizeof(fail_all_unbinds) != sizeof(symbol)) return 12;
	memcpy(&fail_all_unbinds, &symbol, sizeof(symbol));
	symbol = interposer_symbol("amqp_acceptance_fail_amqp_bind_at");
	if (!symbol || sizeof(fail_amqp_bind_at) != sizeof(symbol)) return 12;
	memcpy(&fail_amqp_bind_at, &symbol, sizeof(symbol));
	symbol = interposer_symbol("amqp_acceptance_failed_unbinds");
	if (!symbol || sizeof(failed_unbinds) != sizeof(symbol)) return 12;
	memcpy(&failed_unbinds, &symbol, sizeof(symbol));
	symbol = interposer_symbol("amqp_acceptance_bind_calls");
	if (!symbol || sizeof(bind_calls) != sizeof(symbol)) return 12;
	memcpy(&bind_calls, &symbol, sizeof(symbol));
	symbol = interposer_symbol("amqp_acceptance_deliveries");
	if (!symbol || sizeof(deliveries) != sizeof(symbol)) return 12;
	memcpy(&deliveries, &symbol, sizeof(symbol));
	if (initial_clean || initial_retained) fail_amqp_bind_at(2);
	if (initial_retained) fail_all_unbinds();

	load_status = switch_loadable_module_load_module(AMQP_ACCEPTANCE_MODULE_DIR,
		"mod_amqp", SWITCH_FALSE, &err);
	exists_status = switch_loadable_module_exists("mod_amqp");
	if (initial_clean) {
		int absent = api_reply("amqp", "status", status_text, sizeof(status_text));
		fail_amqp_bind_at(0);
		repeat_status = switch_loadable_module_load_module(AMQP_ACCEPTANCE_MODULE_DIR,
			"mod_amqp", SWITCH_FALSE, &err);
		if (repeat_status == SWITCH_STATUS_SUCCESS)
			api_reply("amqp", "status", reload_text, sizeof(reload_text));
		printf("scenario=%s first_load=%d first_exists=%d api_absent=%d retry_load=%d retry_status=%s\n",
			scenario, (int)load_status, (int)exists_status, absent, (int)repeat_status, reload_text);
		return load_status != SWITCH_STATUS_SUCCESS && exists_status != SWITCH_STATUS_SUCCESS &&
			absent != SWITCH_STATUS_SUCCESS && repeat_status == SWITCH_STATUS_SUCCESS &&
			strstr(reload_text, "state=ACTIVE") ? 0 : 13;
	}
	if (load_status != SWITCH_STATUS_SUCCESS || exists_status != SWITCH_STATUS_SUCCESS) return 11;
	module_handle = dlopen(AMQP_ACCEPTANCE_MODULE_DIR "/mod_amqp.so", RTLD_NOW | RTLD_NOLOAD);
	if (!module_handle) return 14;
	bindings_before = bind_calls();
	if (api_reply("amqp", "status", status_text, sizeof(status_text)) != SWITCH_STATUS_SUCCESS) return 16;
	unload_status = switch_loadable_module_unload_module(NULL, "mod_amqp", SWITCH_FALSE, &err);
	force_status = switch_loadable_module_unload_module(NULL, "mod_amqp", SWITCH_TRUE, &err);
	repeat_status = switch_loadable_module_load_module(AMQP_ACCEPTANCE_MODULE_DIR,
		"mod_amqp", SWITCH_FALSE, &err);
	if (switch_loadable_module_load_module("/usr/local/freeswitch/mod", "mod_commands",
		SWITCH_FALSE, &err) == SWITCH_STATUS_SUCCESS) {
		api_reply("reload", "mod_amqp", reload_text, sizeof(reload_text));
	}
	if (initial_retained) {
		char reload_api[512] = {0};
		api_reply("amqp", NULL, reload_api, sizeof(reload_api));
		if (!strstr(reload_api, "-ERR mod_amqp configuration reload failed")) rc = 17;
	}
	{
		switch_event_t *event = NULL;
		if (switch_event_create(&event, SWITCH_EVENT_DTMF) != SWITCH_STATUS_SUCCESS) return 22;
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "AMQP-Harness", "true");
		switch_event_deliver(&event);
	}
	printf("scenario=%s load=%d unload=%d force=%d repeat=%d exists=%d binds_before=%d binds_after=%d deliveries=%d failed_unbinds=%d dso_resident=%d status=%s reload=%s\n",
		scenario, (int)load_status, (int)unload_status, (int)force_status, (int)repeat_status,
		(int)switch_loadable_module_exists("mod_amqp"), bindings_before, bind_calls(), deliveries(), failed_unbinds(),
		module_handle != NULL, status_text, reload_text);
	if (unload_status != SWITCH_STATUS_NOUNLOAD || force_status != SWITCH_STATUS_NOUNLOAD ||
		repeat_status == SWITCH_STATUS_SUCCESS || switch_loadable_module_exists("mod_amqp") != SWITCH_STATUS_SUCCESS ||
		bind_calls() != bindings_before || deliveries() != 1 ||
		!strstr(reload_text, "-ERR unloading module") || !strstr(reload_text, "-ERR loading module")) rc = 18;
	if (initial_retained) {
		if (!strstr(status_text, "state=RESTART_REQUIRED") || failed_unbinds() < 1) rc = 19;
	} else if (!strstr(status_text, "state=ACTIVE") || failed_unbinds() != 0) rc = 20;
	if (!initial_retained) {
		char config_reload[512] = {0};
		api_reply("amqp", NULL, config_reload, sizeof(config_reload));
		if (!strstr(config_reload, "+OK mod_amqp configuration reloaded")) rc = 21;
	}
	dlclose(module_handle);
	return rc;
}
