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
	stream->write_function(stream, "+OK mod_amqp state=%s restart_required=%s detail=%s\n",
		name, state == MOD_AMQP_HEALTH_RESTART_REQUIRED ? "true" : "false",
		detail ? detail : "none");
}

SWITCH_STANDARD_API(amqp_reload)
{
	if (cmd && !strcmp(cmd, "status")) {
		mod_amqp_write_status(stream);
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
		SWITCH_ADD_API(api_interface, "amqp", "amqp API", amqp_reload, "syntax");
		return SWITCH_STATUS_NOUNLOAD;
	}

	SWITCH_ADD_API(api_interface, "amqp", "amqp API", amqp_reload, "syntax");


	/* Core marks NOUNLOAD as permanent before publishing registry/interfaces. */
	return SWITCH_STATUS_NOUNLOAD;
}

/* ------------------------------
   Shutdown
   ------------------------------
*/
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_amqp_shutdown)
{
	switch_hash_index_t *hi = NULL;
	mod_amqp_producer_profile_t *producer;
	mod_amqp_command_profile_t *command;
	mod_amqp_logging_profile_t *logging;

	if (switch_mutex_trylock(mod_amqp_globals.lifecycle_mutex) != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_NOUNLOAD;
	}
	if (mod_amqp_is_command_thread()) {
		switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
		return SWITCH_STATUS_NOUNLOAD;
	}
	mod_amqp_globals.shutting_down = SWITCH_TRUE;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Mod starting shutting down\n");

	while ((hi = switch_core_hash_first_iter(mod_amqp_globals.producer_hash, hi))) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&producer);
		if (mod_amqp_producer_destroy(&producer) != SWITCH_STATUS_SUCCESS) {
			switch_safe_free(hi);
			switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
			/* Core only preserves the DSO for NOUNLOAD, not for GENERR. */
			return SWITCH_STATUS_NOUNLOAD;
		}
	}

	while ((hi = switch_core_hash_first_iter(mod_amqp_globals.command_hash, hi))) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&command);
		if (mod_amqp_command_destroy(&command) != SWITCH_STATUS_SUCCESS) {
			switch_safe_free(hi);
			switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
			return SWITCH_STATUS_NOUNLOAD;
		}
	}

	if (mod_amqp_globals.logging_bound) {
		if (switch_log_unbind_logger(mod_amqp_logging_recv) != SWITCH_STATUS_SUCCESS) {
			switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
			return SWITCH_STATUS_NOUNLOAD;
		}
		mod_amqp_globals.logging_bound = SWITCH_FALSE;
	}
	while ((hi = switch_core_hash_first_iter(mod_amqp_globals.logging_hash, hi))) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&logging);
		if (mod_amqp_logging_destroy(&logging) != SWITCH_STATUS_SUCCESS) {
			switch_safe_free(hi);
			switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
			return SWITCH_STATUS_NOUNLOAD;
		}
	}

	switch_core_hash_destroy(&(mod_amqp_globals.producer_hash));
	switch_core_hash_destroy(&(mod_amqp_globals.command_hash));
	switch_core_hash_destroy(&(mod_amqp_globals.logging_hash));

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Mod finished shutting down\n");
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
