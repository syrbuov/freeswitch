/* Isolated proof of the forced-unload/config-reload race. */
#include <switch.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static switch_status_t reload_status;
static char reload_reply[256];

static void *reload_thread(void *unused)
{
    switch_stream_handle_t stream = {0};
    (void)unused;
    SWITCH_STANDARD_STREAM(stream);
    reload_status = switch_api_execute("amqp", NULL, NULL, &stream);
    switch_snprintf(reload_reply, sizeof(reload_reply), "%s", stream.data ? (char *)stream.data : "");
    switch_safe_free(stream.data);
    return NULL;
}

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
    void *sym;
    void (*arm)(void), (*release)(void);
    int (*entered)(void);
    pthread_t thread;
    switch_status_t load, unload, exists;
    int i, status_before, status_after;
    void *dso;

    SWITCH_GLOBAL_dirs.mod_dir = strdup(AMQP_PROBE_FIXTURE_ROOT "/conf");
    SWITCH_GLOBAL_dirs.conf_dir = strdup(AMQP_PROBE_FIXTURE_ROOT "/conf");
    SWITCH_GLOBAL_dirs.log_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
    SWITCH_GLOBAL_dirs.run_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
    SWITCH_GLOBAL_dirs.db_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
    SWITCH_GLOBAL_dirs.data_dir = strdup(AMQP_PROBE_FIXTURE_ROOT);
    switch_core_set_globals();
    if (switch_core_init_and_modload(SCF_LOG_DISABLE, SWITCH_TRUE, &err) != SWITCH_STATUS_SUCCESS) return 10;

    sym = dlsym(RTLD_DEFAULT, "amqp_probe_arm_unbind");
    if (!sym) return 11;
    memcpy(&arm, &sym, sizeof(arm));
    sym = dlsym(RTLD_DEFAULT, "amqp_probe_unbind_entered");
    if (!sym) return 11;
    memcpy(&entered, &sym, sizeof(entered));
    sym = dlsym(RTLD_DEFAULT, "amqp_probe_release_unbind");
    if (!sym) return 11;
    memcpy(&release, &sym, sizeof(release));

    load = switch_loadable_module_load_module(AMQP_PROBE_MODULE_DIR, "mod_amqp", SWITCH_FALSE, &err);
    if (load != SWITCH_STATUS_SUCCESS) return 12;
    status_before = status_api_available();
    arm();
    if (pthread_create(&thread, NULL, reload_thread, NULL)) return 13;
    for (i = 0; i < 3000 && !entered(); i++) switch_sleep(1000);
    if (!entered()) {
        release();
        pthread_join(thread, NULL);
        return 14;
    }

    unload = switch_loadable_module_unload_module(NULL, "mod_amqp", SWITCH_TRUE, &err);
    exists = switch_loadable_module_exists("mod_amqp");
    status_after = status_api_available();
    dso = dlopen(AMQP_PROBE_MODULE_DIR "/mod_amqp.so", RTLD_NOW | RTLD_NOLOAD);
    release();
    pthread_join(thread, NULL);
    printf("load=%d forced_unload=%d exists=%d status_before=%d status_after=%d dso_resident=%d reload_status=%d reload_reply=%s\n",
        (int)load, (int)unload, (int)exists, status_before, status_after, dso != NULL,
        (int)reload_status, reload_reply);
    if (dso) dlclose(dso);
    return status_before && entered() && unload == SWITCH_STATUS_SUCCESS &&
        exists != SWITCH_STATUS_SUCCESS && !status_after && dso != NULL ? 0 : 15;
}
