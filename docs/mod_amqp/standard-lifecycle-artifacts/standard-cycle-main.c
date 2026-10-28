/* Isolated control: ordinary load/unload cycles on the one-line nonpermanent copy. */
#include <switch.h>
#include <stdio.h>
#include <string.h>

static int status_api_available(void)
{
    switch_stream_handle_t stream = {0};
    switch_status_t status;
    SWITCH_STANDARD_STREAM(stream);
    status = switch_api_execute("amqp", "status", NULL, &stream);
    switch_safe_free(stream.data);
    return status == SWITCH_STATUS_SUCCESS;
}

int main(void)
{
    const char *err = NULL;
    int cycle;
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
        switch_status_t unload;
        if (load != SWITCH_STATUS_SUCCESS || !status_api_available()) return 11;
        unload = switch_loadable_module_unload_module(NULL, "mod_amqp", SWITCH_FALSE, &err);
        printf("cycle=%d load=%d unload=%d exists=%d api=%d\n", cycle,
            (int)load, (int)unload, (int)switch_loadable_module_exists("mod_amqp"),
            status_api_available());
        if (unload != SWITCH_STATUS_SUCCESS ||
            switch_loadable_module_exists("mod_amqp") == SWITCH_STATUS_SUCCESS ||
            status_api_available()) return 12;
    }
    return switch_core_destroy() == SWITCH_STATUS_SUCCESS ? 0 : 13;
}
