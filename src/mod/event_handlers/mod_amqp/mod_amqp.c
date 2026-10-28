/*
* FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
* Copyright (C) 2005-2012, Anthony Minessale II <anthm@freeswitch.org>
*
* Version: MPL 1.1
*
* The contents of this file are subject to the Mozilla Public License Version
* 1.1 (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
* for the specific language governing rights and limitations under the
* License.
*
* The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
*
* The Initial Developer of the Original Code is
* Anthony Minessale II <anthm@freeswitch.org>
* Portions created by the Initial Developer are Copyright (C)
* the Initial Developer. All Rights Reserved.
*
* Based on mod_skel by
* Anthony Minessale II <anthm@freeswitch.org>
*
* Contributor(s):
*
* Daniel Bryars <danb@aeriandi.com>
* Tim Brown <tim.brown@aeriandi.com>
* Anthony Minessale II <anthm@freeswitch.org>
* William King <william.king@quentustech.com>
* Mike Jerris <mike@jerris.com>
*
* mod_amqp.c -- Sends FreeSWITCH events to an AMQP broker
*
*/

#include "mod_amqp.h"

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_amqp_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_amqp_load);
SWITCH_MODULE_DEFINITION(mod_amqp, mod_amqp_load, mod_amqp_shutdown, NULL);

mod_amqp_globals_t mod_amqp_globals;

void mod_amqp_health_set(mod_amqp_health_t state, const char *detail)
{
	switch_mutex_lock(mod_amqp_globals.health_mutex);
	mod_amqp_globals.health = state;
	mod_amqp_globals.health_detail = detail;
	switch_mutex_unlock(mod_amqp_globals.health_mutex);
}

void mod_amqp_health_note(const char *detail)
{
	switch_mutex_lock(mod_amqp_globals.health_mutex);
	mod_amqp_globals.health_detail = detail;
	switch_mutex_unlock(mod_amqp_globals.health_mutex);
}

static void mod_amqp_write_status(switch_stream_handle_t *stream)
{
	mod_amqp_health_t state;
	const char *detail;
	const char *name;
	switch_mutex_lock(mod_amqp_globals.health_mutex);
	state = mod_amqp_globals.health;
	detail = mod_amqp_globals.health_detail;
	switch_mutex_unlock(mod_amqp_globals.health_mutex);
	name = state == MOD_AMQP_HEALTH_ACTIVE ? "ACTIVE" :
		state == MOD_AMQP_HEALTH_DEGRADED ? "DEGRADED" : "RESTART_REQUIRED";
	stream->write_function(stream, "+OK mod_amqp state=%s restart_required=%s commands=legacy-local-test detail=%s\n",
		name, state == MOD_AMQP_HEALTH_RESTART_REQUIRED ? "true" : "false",
		detail ? detail : "none");
}

/* lifecycle_mutex protects profile ownership; profile mutex protects the
 * worker/callback snapshot. JSON owns all names before releasing lifecycle. */
static cJSON *mod_amqp_profile_snapshot(const char *name, mod_amqp_io_t *io,
    switch_bool_t *running, switch_queue_t *queue, unsigned int capacity,
    switch_bool_t join_pending)
{
    static const char *counter_names[] = {
        "connect_attempts", "connect_failures", "publish_ok", "publish_errors",
        "enqueued", "dropped", "filtered"
    };
    mod_amqp_io_t snapshot;
    switch_bool_t enabled;
    cJSON *entry = cJSON_CreateObject();
    const char *state;
    size_t i;
    if (!entry) return NULL;
    switch_mutex_lock(io->mutex);
    snapshot = *io;
    enabled = *running;
    switch_mutex_unlock(io->mutex);
    state = snapshot.state == MOD_AMQP_IO_READY ? "ready" :
        snapshot.state == MOD_AMQP_IO_CONNECTING ? "connecting" :
        snapshot.state == MOD_AMQP_IO_STOPPED ? "stopped" : "disconnected";
    cJSON_AddStringToObject(entry, "name", name);
    cJSON_AddBoolToObject(entry, "enabled", enabled);
    cJSON_AddBoolToObject(entry, "worker_running", snapshot.worker_running);
    cJSON_AddBoolToObject(entry, "join_pending", join_pending);
    cJSON_AddStringToObject(entry, "connection", state);
    cJSON_AddStringToObject(entry, "last_error", snapshot.last_error ? snapshot.last_error : "none");
    cJSON_AddNumberToObject(entry, "queue_depth", queue ? switch_queue_size(queue) : 0);
    cJSON_AddNumberToObject(entry, "queue_capacity", capacity);
    for (i = 0; i < MOD_AMQP_COUNTER_COUNT; i++) {
        char value[32];
        /* Preserve full uint64 precision for machine readers. */
        switch_snprintf(value, sizeof(value), "%" SWITCH_UINT64_T_FMT, snapshot.counters[i]);
        cJSON_AddStringToObject(entry, counter_names[i], value);
    }
    if (cJSON_GetArraySize(entry) != 8 + MOD_AMQP_COUNTER_COUNT) {
        cJSON_Delete(entry);
        return NULL;
    }
    return entry;
}

static void mod_amqp_write_profiles(switch_stream_handle_t *stream)
{
    switch_hash_index_t *hi = NULL;
    cJSON *root, *producers, *logging, *entry;
    char *json;
    if (switch_mutex_trylock(mod_amqp_globals.lifecycle_mutex) != SWITCH_STATUS_SUCCESS) {
        stream->write_function(stream, "-ERR mod_amqp profile snapshot busy\n");
        return;
    }
    root = cJSON_CreateObject();
    producers = cJSON_CreateArray();
    logging = cJSON_CreateArray();
    if (!root || !producers || !logging) {
        cJSON_Delete(root); cJSON_Delete(producers); cJSON_Delete(logging);
        switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
        stream->write_function(stream, "-ERR mod_amqp profile snapshot allocation failed\n");
        return;
    }
    cJSON_AddStringToObject(root, "commands", "legacy-local-test");
    cJSON_AddItemToObject(root, "producers", producers);
    cJSON_AddItemToObject(root, "logging", logging);
    for (hi = mod_amqp_globals.producer_hash ? switch_core_hash_first(mod_amqp_globals.producer_hash) : NULL;
         hi; hi = switch_core_hash_next(&hi)) {
        mod_amqp_producer_profile_t *profile;
        switch_core_hash_this(hi, NULL, NULL, (void **)&profile);
        entry = mod_amqp_profile_snapshot(profile->name, &profile->io, &profile->running,
            profile->send_queue, profile->send_queue_size, profile->producer_thread != NULL);
        if (!entry) goto failed;
        cJSON_AddBoolToObject(entry, "retained", profile->activation_state == MOD_AMQP_PRODUCER_RETAINED);
        cJSON_AddItemToArray(producers, entry);
    }
    for (hi = mod_amqp_globals.logging_hash ? switch_core_hash_first(mod_amqp_globals.logging_hash) : NULL;
         hi; hi = switch_core_hash_next(&hi)) {
        mod_amqp_logging_profile_t *profile;
        switch_core_hash_this(hi, NULL, NULL, (void **)&profile);
        entry = mod_amqp_profile_snapshot(profile->name, &profile->io, &profile->running,
            profile->send_queue, profile->send_queue_size, profile->logging_thread != NULL);
        if (!entry) goto failed;
        cJSON_AddItemToArray(logging, entry);
    }
    switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
    json = cJSON_PrintUnformatted(root);
    if (json) stream->write_function(stream, "+OK mod_amqp profiles\n%s\n", json);
    else stream->write_function(stream, "-ERR mod_amqp profile snapshot allocation failed\n");
    switch_safe_free(json);
    cJSON_Delete(root);
    return;
 failed:
    switch_safe_free(hi);
    switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
    cJSON_Delete(root);
    stream->write_function(stream, "-ERR mod_amqp profile snapshot allocation failed\n");
}

SWITCH_STANDARD_API(amqp_reload)
{
	if (cmd && !strcmp(cmd, "status")) {
		mod_amqp_write_status(stream);
		return SWITCH_STATUS_SUCCESS;
	}
	if (cmd && !strcmp(cmd, "profiles")) {
		mod_amqp_write_profiles(stream);
		return SWITCH_STATUS_SUCCESS;
	}
	if (!zstr(cmd) && strcmp(cmd, "reload")) {
		stream->write_function(stream, "-ERR usage: amqp [reload|status|profiles]\n");
		return SWITCH_STATUS_SUCCESS;
	}
	/* Core appends a generic error for non-success API status; ESL replaces
	 * that stream with "Command not found". Report the reload operation in
	 * the stream and return success for the completed API invocation. */
	if (mod_amqp_do_config(SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
		stream->write_function(stream, "+OK mod_amqp configuration reloaded\n");
	} else {
		stream->write_function(stream, "-ERR mod_amqp configuration reload failed\n");
	}
	return SWITCH_STATUS_SUCCESS;
}


/* ------------------------------
   Startup
   ------------------------------
*/
SWITCH_MODULE_LOAD_FUNCTION(mod_amqp_load)
{
	switch_api_interface_t *api_interface;

	/* A retained generation must never lose its owners to a second load. */
	if (mod_amqp_globals.pool) return SWITCH_STATUS_GENERR;
	memset(&mod_amqp_globals, 0, sizeof(mod_amqp_globals_t));
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	mod_amqp_globals.pool = pool;
	if (switch_mutex_init(&mod_amqp_globals.lifecycle_mutex, SWITCH_MUTEX_UNNESTED, pool) != SWITCH_STATUS_SUCCESS) {
		memset(&mod_amqp_globals, 0, sizeof(mod_amqp_globals));
		return SWITCH_STATUS_GENERR;
	}
	if (switch_mutex_init(&mod_amqp_globals.health_mutex, SWITCH_MUTEX_UNNESTED, pool) != SWITCH_STATUS_SUCCESS) {
		memset(&mod_amqp_globals, 0, sizeof(mod_amqp_globals));
		return SWITCH_STATUS_GENERR;
	}
	mod_amqp_health_set(MOD_AMQP_HEALTH_DEGRADED, "initial activation in progress");
	switch_core_hash_init(&(mod_amqp_globals.producer_hash));
	switch_core_hash_init(&(mod_amqp_globals.command_hash));
	switch_core_hash_init(&(mod_amqp_globals.logging_hash));

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_apqp loading: Version %s\n", switch_version_full());

	/* Create producer profiles */
	if (mod_amqp_do_config(SWITCH_FALSE) != SWITCH_STATUS_SUCCESS) {
		if (mod_amqp_shutdown() == SWITCH_STATUS_SUCCESS) {
			memset(&mod_amqp_globals, 0, sizeof(mod_amqp_globals));
			return SWITCH_STATUS_GENERR;
		}
		/* Core accepts NOUNLOAD on load and pins the DSO. Retained callback or
		 * worker resources must never point into an unloaded module. */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "AMQP configuration failed and cleanup retained resources; pinning module\n");
		mod_amqp_health_set(MOD_AMQP_HEALTH_RESTART_REQUIRED,
			"initial activation failed; cleanup retained resources; process restart required");
		SWITCH_ADD_API(api_interface, "amqp", "amqp API", amqp_reload, "[reload|status|profiles]");
		return SWITCH_STATUS_NOUNLOAD;
	}

	SWITCH_ADD_API(api_interface, "amqp", "amqp API", amqp_reload, "[reload|status|profiles]");


	/* Ordinary modules receive Core's process-shutdown callback. Permanent
	 * modules do not, leaving workers alive while Core destroys their services. */
	return SWITCH_STATUS_SUCCESS;
}

/* ------------------------------
   Shutdown
   ------------------------------
*/
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_amqp_shutdown)
{
	switch_hash_index_t *hi;
	mod_amqp_producer_profile_t *producer;
	mod_amqp_command_profile_t *command;
	mod_amqp_logging_profile_t *logging;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	/* Legacy console execution is for local tests only: management commands
	 * from its worker are unsupported. External shutdown waits for an in-flight
	 * config reload; returning early would lose Core's registry after unprocess. */
	switch_mutex_lock(mod_amqp_globals.lifecycle_mutex);
	if (mod_amqp_is_command_thread()) {
		switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
		return SWITCH_STATUS_NOUNLOAD;
	}
	mod_amqp_globals.shutting_down = SWITCH_TRUE;

	/* Try each owner once, advancing before destroy removes its hash entry.
	 * A retained profile must not leave unrelated workers running at shutdown. */
	for (hi = switch_core_hash_first(mod_amqp_globals.producer_hash); hi;) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&producer);
		hi = switch_core_hash_next(&hi);
		if (mod_amqp_producer_destroy(&producer) != SWITCH_STATUS_SUCCESS) {
			mod_amqp_health_set(MOD_AMQP_HEALTH_RESTART_REQUIRED, "producer cleanup failed; process restart required");
			status = SWITCH_STATUS_GENERR;
		}
	}
	for (hi = switch_core_hash_first(mod_amqp_globals.command_hash); hi;) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&command);
		hi = switch_core_hash_next(&hi);
		if (mod_amqp_command_destroy(&command) != SWITCH_STATUS_SUCCESS) {
			mod_amqp_health_set(MOD_AMQP_HEALTH_RESTART_REQUIRED, "command cleanup failed; process restart required");
			status = SWITCH_STATUS_GENERR;
		}
	}
	if (mod_amqp_globals.logging_bound) {
		if (switch_log_unbind_logger(mod_amqp_logging_recv) == SWITCH_STATUS_SUCCESS) {
			mod_amqp_globals.logging_bound = SWITCH_FALSE;
		} else {
			mod_amqp_health_set(MOD_AMQP_HEALTH_RESTART_REQUIRED, "logger unbind failed; process restart required");
			status = SWITCH_STATUS_GENERR;
		}
	}
	for (hi = switch_core_hash_first(mod_amqp_globals.logging_hash); hi;) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&logging);
		hi = switch_core_hash_next(&hi);
		if (mod_amqp_globals.logging_bound) {
			/* Callback may still read the hash/queue: request stop but retain
			 * every owner until a subsequent successful unbind. */
			mod_amqp_logging_stop(logging);
		} else if (mod_amqp_logging_destroy(&logging) != SWITCH_STATUS_SUCCESS) {
			mod_amqp_health_set(MOD_AMQP_HEALTH_RESTART_REQUIRED, "logging cleanup failed; process restart required");
			status = SWITCH_STATUS_GENERR;
		}
	}
	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "AMQP shutdown retained resources; process restart required\n");
		switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
		/* Core only keeps the DSO/pool for NOUNLOAD, not for GENERR. */
		return SWITCH_STATUS_NOUNLOAD;
	}
	switch_core_hash_destroy(&mod_amqp_globals.producer_hash);
	switch_core_hash_destroy(&mod_amqp_globals.command_hash);
	switch_core_hash_destroy(&mod_amqp_globals.logging_hash);
	/* Also permit a clean reload if an external dlopen still holds this DSO. */
	mod_amqp_globals.pool = NULL;
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	return SWITCH_STATUS_SUCCESS;
}


/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4
 */
