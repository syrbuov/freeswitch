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

/* Shared only by the manager and sender. Keep lock scope outside queue and
 * AMQP calls; a blocked I/O call may still delay the subsequent join. */
static void mod_amqp_logging_set_running(mod_amqp_logging_profile_t *profile, switch_bool_t running)
{
	switch_mutex_lock(profile->mutex);
	profile->running = running;
	if (!running && profile->stop_cond) switch_thread_cond_broadcast(profile->stop_cond);
	switch_mutex_unlock(profile->mutex);
}

static switch_bool_t mod_amqp_logging_is_running(mod_amqp_logging_profile_t *profile)
{
	switch_bool_t running;
	switch_mutex_lock(profile->mutex);
	running = profile->running;
	switch_mutex_unlock(profile->mutex);
	return running;
}

switch_status_t mod_amqp_logging_recv(const switch_log_node_t *node, switch_log_level_t level)
{
	switch_hash_index_t *hi = NULL;
	mod_amqp_message_t *msg = NULL;
	mod_amqp_logging_profile_t *logging = NULL;
	char *json = NULL;

	if (!strcmp(node->file, "mod_amqp_logging.c")) {
		return SWITCH_STATUS_SUCCESS;
	}

	/*
	  1. Loop through logging hash of profiles. Check for a profile that accepts this logging level, and file regex.
	  2. If event not already parsed/created, then create it now
	  3. Queue copy of event into logging profile send queue
	  4. Destroy local event copy
	*/
	for (hi = switch_core_hash_first(mod_amqp_globals.logging_hash); hi; hi = switch_core_hash_next(&hi)) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&logging);

		if ( logging && switch_log_check_mask(logging->log_level_mask, level) ) {
			char file[128] = {0};
			if ( !json ) {
				cJSON *body = NULL;
				char date[80] = "";
				switch_time_exp_t tm;

				switch_time_exp_lt(&tm, node->timestamp);
				switch_snprintf(date, sizeof(date), "%0.4d-%0.2d-%0.2d %0.2d:%0.2d:%0.2d.%0.6d",
								tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec);

				/* Create cJSON body */
				body = cJSON_CreateObject();

				cJSON_AddItemToObject(body, "file", cJSON_CreateString((const char *) node->file));
				cJSON_AddItemToObject(body, "function", cJSON_CreateString((const char *) node->func));
				cJSON_AddItemToObject(body, "line", cJSON_CreateNumber((double) node->line));
				cJSON_AddItemToObject(body, "level", cJSON_CreateString(switch_log_level2str(node->level)));
				cJSON_AddItemToObject(body, "timestamp", cJSON_CreateString((const char *)date));
				cJSON_AddItemToObject(body, "timestamp_epoch", cJSON_CreateNumber((double) node->timestamp / 1000000));
				cJSON_AddItemToObject(body, "content", cJSON_CreateString(node->content ));

				json = cJSON_Print(body);
				cJSON_Delete(body);
			}

			/* Create message */
			switch_malloc(msg, sizeof(mod_amqp_message_t));
			msg->pjson = strdup(json);
			switch_copy_string(file, node->file, sizeof(file));
			switch_replace_char(file, '.', '_', 0);

			snprintf(msg->routing_key, sizeof(msg->routing_key), "%s.%s.%s.%s", switch_core_get_hostname(), node->userdata, switch_log_level2str(node->level), file);

			if (switch_queue_trypush(logging->send_queue, msg) != SWITCH_STATUS_SUCCESS) {
				mod_amqp_io_count(&logging->io, MOD_AMQP_DROPPED);
				mod_amqp_util_msg_destroy(&msg);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "AMQP logging message queue full. Messages will be dropped!\n");
				switch_safe_free(hi);
				goto done;
			}
			mod_amqp_io_count(&logging->io, MOD_AMQP_ENQUEUED);
		}
	}

 done:
	switch_safe_free(json);
	return SWITCH_STATUS_SUCCESS;
}

void mod_amqp_logging_stop(mod_amqp_logging_profile_t *profile)
{
	if (profile->mutex) mod_amqp_logging_set_running(profile, SWITCH_FALSE);
	if (profile->send_queue) switch_queue_interrupt_all(profile->send_queue);
	mod_amqp_io_stop(&profile->io);
}

switch_status_t mod_amqp_logging_destroy(mod_amqp_logging_profile_t **prof)
{
	mod_amqp_message_t *msg = NULL;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	mod_amqp_connection_t *conn = NULL, *conn_next = NULL;
	switch_memory_pool_t *pool;
	mod_amqp_logging_profile_t *profile;

	if (!prof || !*prof) {
		return SWITCH_STATUS_SUCCESS;
	}

	profile = *prof;
	pool = profile->pool;

	if (profile->name) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Profile[%s] shutting down...\n", profile->name);
	}

	mod_amqp_logging_stop(profile);

	if (profile->logging_thread) {
		if (switch_thread_join(&status, profile->logging_thread) != SWITCH_STATUS_SUCCESS) return SWITCH_STATUS_GENERR;
		profile->logging_thread = NULL;
	}

	if (profile->name && switch_core_hash_find(mod_amqp_globals.logging_hash, profile->name) == profile) {
		switch_core_hash_delete(mod_amqp_globals.logging_hash, profile->name);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Profile[%s] closing AMQP socket...\n", profile->name);

	for (conn = profile->conn_root; conn; conn = conn_next) {
		conn_next = conn->next;
		mod_amqp_connection_destroy(&conn);
	}

	profile->conn_active = NULL;
	profile->conn_root = NULL;

	while (profile->send_queue && switch_queue_trypop(profile->send_queue, (void**)&msg) == SWITCH_STATUS_SUCCESS) {
		mod_amqp_io_count(&profile->io, MOD_AMQP_DROPPED);
		mod_amqp_util_msg_destroy(&msg);
	}

	if (pool) {
		switch_core_destroy_memory_pool(&pool);
	}

	*prof = NULL;

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t mod_amqp_logging_create(char *name, switch_xml_t cfg)
{
	mod_amqp_logging_profile_t *profile = NULL;
	switch_xml_t params, param, connections, connection;
	switch_threadattr_t *thd_attr = NULL;
	switch_thread_t *worker = NULL;
	switch_queue_t *queue = NULL;
	char *exchange = NULL, *exchange_type = NULL;
	int exchange_durable = 1; /* durable */
	switch_memory_pool_t *pool;

	if (zstr(name) || switch_core_hash_find(mod_amqp_globals.logging_hash, name)) return SWITCH_STATUS_GENERR;

	if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
		goto err;
	}

	profile = switch_core_alloc(pool, sizeof(mod_amqp_logging_profile_t));
	profile->pool = pool;
	profile->name = switch_core_strdup(profile->pool, name);
	if (switch_mutex_init(&profile->mutex, SWITCH_MUTEX_NESTED, pool) != SWITCH_STATUS_SUCCESS) {
		profile->mutex = NULL;
		goto err;
	}
	if (switch_thread_cond_create(&profile->stop_cond, pool) != SWITCH_STATUS_SUCCESS) {
		profile->stop_cond = NULL;
		goto err;
	}
	profile->io.mutex = profile->mutex;
	profile->io.fd = -1;
	mod_amqp_logging_set_running(profile, SWITCH_TRUE);
	profile->conn_root   = NULL;
	profile->conn_active = NULL;
	profile->log_level_mask = 0;
	profile->send_queue_size = 5000;
	profile->reconnect_interval_ms = 1000;

	if ((params = switch_xml_child(cfg, "params")) != NULL) {
		for (param = switch_xml_child(params, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (!var) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Profile[%s] param missing 'name' attribute\n", profile->name);
				continue;
			}

			if (!val) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Profile[%s] param[%s] missing 'value' attribute\n", profile->name, var);
				continue;
			}

			if (!strncmp(var, "reconnect_interval_ms", 21)) {
				int interval = atoi(val);
				if ( interval && interval > 0 ) {
					profile->reconnect_interval_ms = interval;
				}
			} else if (!strncmp(var, "send_queue_size", 15)) {
				int interval = atoi(val);
				if ( interval && interval > 0 ) {
					profile->send_queue_size = interval;
				}
			} else if (!strncmp(var, "exchange-type", 13)) {
				exchange_type = switch_core_strdup(profile->pool, val);
			} else if (!strncmp(var, "exchange-name", 13)) {
				exchange = switch_core_strdup(profile->pool, val);
			} else if (!strncmp(var, "exchange-durable", 16)) {
				exchange_durable = switch_true(val);
			} else if (!strncmp(var, "log-levels", 10)) {
			  profile->log_level_mask = switch_log_str2mask(val);
			}
		} /* params for loop */
	}

	/* Handle defaults of string types */
	profile->exchange = exchange ? exchange : switch_core_strdup(profile->pool, "TAP.Events");
	profile->exchange_type = exchange_type ? exchange_type : switch_core_strdup(profile->pool, "topic");
	profile->exchange_durable = exchange_durable;

	if ((connections = switch_xml_child(cfg, "connections")) != NULL) {
		for (connection = switch_xml_child(connections, "connection"); connection; connection = connection->next) {
			if ( ! profile->conn_root ) { /* Handle first root node */
				if (mod_amqp_connection_create(&(profile->conn_root), connection, profile->pool) != SWITCH_STATUS_SUCCESS) {
					/* Handle connection create failure */
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Profile[%s] failed to create connection\n", profile->name);
					continue;
				}
				profile->conn_active = profile->conn_root;
			} else {
				if (mod_amqp_connection_create(&(profile->conn_active->next), connection, profile->pool) != SWITCH_STATUS_SUCCESS) {
					/* Handle connection create failure */
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Profile[%s] failed to create connection\n", profile->name);
					continue;
				}
				profile->conn_active = profile->conn_active->next;
			}
		}
	}
	profile->conn_active = NULL;
	/* We are not going to open the logging queue connection on create, but instead wait for the running thread to open it */

	/* Create a bounded FIFO queue for sending messages */
	if (switch_queue_create(&queue, profile->send_queue_size, profile->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot create send queue of size %d!\n", profile->send_queue_size);
		goto err;
	}

	profile->send_queue = queue;

	/* Start the event send thread. This will set up the initial connection */
	/* Publish the owner before starting a worker, so failed join cleanup remains reachable. */
	if (switch_core_hash_insert(mod_amqp_globals.logging_hash, name, profile) != SWITCH_STATUS_SUCCESS) goto err;
	if (switch_threadattr_create(&thd_attr, profile->pool) != SWITCH_STATUS_SUCCESS ||
		switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE) != SWITCH_STATUS_SUCCESS ||
		switch_threadattr_detach_set(thd_attr, 0) != SWITCH_STATUS_SUCCESS ||
		switch_thread_create(&worker, thd_attr, mod_amqp_logging_thread, profile, profile->pool) != SWITCH_STATUS_SUCCESS) {
		goto err;
	}
	profile->logging_thread = worker;

	return SWITCH_STATUS_SUCCESS;

 err:
	/* Cleanup */
	if (mod_amqp_logging_destroy(&profile) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "AMQP logging cleanup failed; retaining owner\n");
	}
	return SWITCH_STATUS_GENERR;

}

/* This should only be called in a single threaded context from the logging profile send thread */
switch_status_t mod_amqp_logging_send(mod_amqp_logging_profile_t *profile, mod_amqp_message_t *msg)
{
	amqp_basic_properties_t props;
	int status;

	if (! profile->conn_active) {
		/* No connection, so we can not send the message. */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Profile[%s] not active\n", profile->name);
		return SWITCH_STATUS_NOT_INITALIZED;
	}
	memset(&props, 0, sizeof(amqp_basic_properties_t));

	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG;
	props.content_type = amqp_cstring_bytes("application/json");

	status = amqp_basic_publish(
								profile->conn_active->state,
								1,
								amqp_cstring_bytes(profile->exchange),
								amqp_cstring_bytes(msg->routing_key),
								0,
								0,
								&props,
								amqp_cstring_bytes(msg->pjson));

	if (status < 0) {
		const char *errstr = amqp_error_string2(status);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Profile[%s] failed to send event on connection[%s]: %s\n",
						  profile->name, profile->conn_active->name, errstr);

		mod_amqp_io_count(&profile->io, MOD_AMQP_PUBLISH_ERRORS);
		mod_amqp_io_state(&profile->io, MOD_AMQP_IO_DISCONNECTED, "publish");
		/* This is bad, we couldn't send the message. Clear up any connection */
		mod_amqp_connection_close(profile->conn_active);
		profile->conn_active = NULL;
		return SWITCH_STATUS_SOCKERR;
	}

	mod_amqp_io_count(&profile->io, MOD_AMQP_PUBLISH_OK);
	return SWITCH_STATUS_SUCCESS;
}



void * SWITCH_THREAD_FUNC mod_amqp_logging_thread(switch_thread_t *thread, void *data)
{
  mod_amqp_message_t *msg = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  mod_amqp_logging_profile_t *profile = (mod_amqp_logging_profile_t *)data;
  amqp_boolean_t passive = 0;
  amqp_boolean_t durable = 1;

  mod_amqp_io_worker(&profile->io, SWITCH_TRUE);
  while (mod_amqp_logging_is_running(profile)) {
    if (!profile->conn_active) {
      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Amqp no connection- reconnecting...\n");

      status = mod_amqp_connection_open(profile->conn_root, &(profile->conn_active), profile->name, profile->custom_attr, &profile->io);
      if ( status	== SWITCH_STATUS_SUCCESS ) {
		  // Ensure that the exchange exists, and is of the correct type
#if AMQP_VERSION_MAJOR == 0 && AMQP_VERSION_MINOR >= 6
		  amqp_exchange_declare(profile->conn_active->state, 1,
								amqp_cstring_bytes(profile->exchange),
								amqp_cstring_bytes(profile->exchange_type),
								passive,
								durable,
								profile->exchange_auto_delete,
								0,
								amqp_empty_table);
#else		  
		  amqp_exchange_declare(profile->conn_active->state, 1,
								amqp_cstring_bytes(profile->exchange),
								amqp_cstring_bytes(profile->exchange_type),
								passive,
								durable,
								amqp_empty_table);
#endif

	if (!mod_amqp_log_if_amqp_error(amqp_get_rpc_reply(profile->conn_active->state), "Declaring exchange")) {
	  mod_amqp_io_state(&profile->io, MOD_AMQP_IO_READY, NULL);
	  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Amqp reconnect successful- connected\n");
	  continue;
	}
        mod_amqp_io_count(&profile->io, MOD_AMQP_CONNECT_FAILURES);
        mod_amqp_io_state(&profile->io, MOD_AMQP_IO_DISCONNECTED, "exchange_declare");
        mod_amqp_connection_close(profile->conn_active);
        profile->conn_active = NULL;
        status = SWITCH_STATUS_GENERR;
      }

      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Profile[%s] failed to connect with code(%d), sleeping for %dms\n",
			profile->name, status, profile->reconnect_interval_ms);
      mod_amqp_worker_wait(profile->mutex, profile->stop_cond, &profile->running, profile->reconnect_interval_ms);
      continue;
    }

    if (!msg && switch_queue_pop_timeout(profile->send_queue, (void**)&msg, 1000000) != SWITCH_STATUS_SUCCESS) {
      continue;
    }

    if (msg && mod_amqp_logging_is_running(profile)) {
      switch (mod_amqp_logging_send(profile, msg)) {
      case SWITCH_STATUS_SUCCESS:
	/* Success: prepare for next message */
	mod_amqp_util_msg_destroy(&msg);
	break;

      case SWITCH_STATUS_NOT_INITALIZED:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Send failed with 'not initialised'\n");
	break;

      case SWITCH_STATUS_SOCKERR:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Send failed with 'socket error'\n");
        mod_amqp_worker_wait(profile->mutex, profile->stop_cond, &profile->running, profile->reconnect_interval_ms);
	break;

      default:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Send failed with a generic error\n");

	/* Send failed and closed the connection; reconnect will happen at the beginning of the loop
	 * NB: do we need a delay here to prevent a fast reconnect-send-fail loop? */
	break;
      }
    }
  }

  /* Abort the current message */
  if (msg) mod_amqp_io_count(&profile->io, MOD_AMQP_DROPPED);
  mod_amqp_util_msg_destroy(&msg);
  mod_amqp_io_worker(&profile->io, SWITCH_FALSE);

  // Terminate the thread
  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Event sender thread stopped\n");
  switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
  return NULL;
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
