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

#ifndef WIN32
#include <sys/socket.h>
#include <fcntl.h>
#endif

#if AMQP_VERSION < AMQP_VERSION_CODE(0, 9, 0, 0)
#error mod_amqp lifecycle requires rabbitmq-c 0.9.0 or newer
#endif

void mod_amqp_io_state(mod_amqp_io_t *io, mod_amqp_io_state_t state, const char *error)
{
	if (!io || !io->mutex) return;
	switch_mutex_lock(io->mutex);
	if (!io->stopped) io->state = state;
	if (error) io->last_error = error;
	switch_mutex_unlock(io->mutex);
}

void mod_amqp_io_count(mod_amqp_io_t *io, mod_amqp_counter_t counter)
{
	if (!io || !io->mutex) return;
	switch_mutex_lock(io->mutex);
	io->counters[counter]++;
	switch_mutex_unlock(io->mutex);
}

void mod_amqp_io_worker(mod_amqp_io_t *io, switch_bool_t running)
{
	if (!io || !io->mutex) return;
	switch_mutex_lock(io->mutex);
	io->worker_running = running;
	switch_mutex_unlock(io->mutex);
}

static void mod_amqp_io_release(mod_amqp_io_t *io)
{
	if (!io || !io->mutex) return;
	switch_mutex_lock(io->mutex);
	if (io->fd >= 0) {
#ifdef WIN32
		closesocket(io->fd);
#else
		close(io->fd);
#endif
		io->fd = -1;
	}
	if (!io->stopped) io->state = MOD_AMQP_IO_DISCONNECTED;
	switch_mutex_unlock(io->mutex);
}

void mod_amqp_io_stop(mod_amqp_io_t *io)
{
	if (!io || !io->mutex) return;
	switch_mutex_lock(io->mutex);
	io->stopped = SWITCH_TRUE;
	io->state = MOD_AMQP_IO_STOPPED;
	if (io->fd >= 0) {
#ifdef WIN32
		shutdown(io->fd, SD_BOTH);
#else
		shutdown(io->fd, SHUT_RDWR);
#endif
	}
	switch_mutex_unlock(io->mutex);
}

static switch_bool_t mod_amqp_io_stopped(mod_amqp_io_t *io)
{
	switch_bool_t stopped = SWITCH_FALSE;
	if (!io) return SWITCH_FALSE;
	switch_mutex_lock(io->mutex);
	stopped = io->stopped;
	switch_mutex_unlock(io->mutex);
	return stopped;
}

static switch_status_t mod_amqp_io_register(mod_amqp_io_t *io, int fd)
{
	int copy;
	if (!io) return SWITCH_STATUS_SUCCESS;
#ifdef WIN32
	{
		WSAPROTOCOL_INFO info;
		if (WSADuplicateSocket(fd, GetCurrentProcessId(), &info)) return SWITCH_STATUS_GENERR;
		copy = (int)WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0, 0);
	}
#else
	copy = dup(fd);
	if (copy >= 0 && fcntl(copy, F_SETFD, FD_CLOEXEC) < 0) {
		close(copy);
		copy = -1;
	}
#endif
	if (copy < 0) return SWITCH_STATUS_GENERR;
	switch_mutex_lock(io->mutex);
	io->fd = copy;
	if (io->stopped) {
		switch_mutex_unlock(io->mutex);
		mod_amqp_io_release(io);
		return SWITCH_STATUS_GENERR;
	}
	switch_mutex_unlock(io->mutex);
	return SWITCH_STATUS_SUCCESS;
}

void mod_amqp_connection_close(mod_amqp_connection_t *connection)
{
	amqp_connection_state_t old_state = connection->state;
	connection->state = NULL;
	/* Teardown is local: protocol close RPCs must not wait for a dead broker.
	 * The worker owns rabbitmq-c until join; management only shuts down a dup. */
	mod_amqp_io_release(connection->io);
	connection->io = NULL;
	if (old_state) amqp_destroy_connection(old_state);
}

switch_status_t mod_amqp_connection_open(mod_amqp_connection_t *connections, mod_amqp_connection_t **active, char *profile_name, char *custom_attr, mod_amqp_io_t *io)
{
	int channel_max = 0;
	int frame_max = 131072;
	amqp_table_t loginProperties;
	amqp_table_entry_t loginTableEntries[5];
	char hostname[64];
	int bHasHostname;
	char key_string[5][256] = {{0}};
	const char *attribute = custom_attr ? custom_attr : "";
	const char *phase = "connect";
	amqp_rpc_reply_t status;
	amqp_socket_t *socket = NULL;
	int amqp_status = -1;
	mod_amqp_connection_t *connection_attempt = NULL;
	amqp_connection_state_t newConnection = NULL;
	struct timeval connect_timeout, rpc_timeout;

	if (active && *active) {
		mod_amqp_connection_close(*active);
		*active = NULL;
	}

	/* Set up meta data for connection */
	bHasHostname = gethostname(hostname, sizeof(hostname)) == 0;
	hostname[sizeof(hostname) - 1] = '\0';

	loginProperties.num_entries = sizeof(loginTableEntries)/sizeof(*loginTableEntries);
	loginProperties.entries = loginTableEntries;

	snprintf(key_string[0], sizeof(key_string[0]), "x_%s_HostMachineName", attribute);
	loginTableEntries[0].key = amqp_cstring_bytes(key_string[0]);
	loginTableEntries[0].value.kind = AMQP_FIELD_KIND_BYTES;
	loginTableEntries[0].value.value.bytes = amqp_cstring_bytes(bHasHostname ? hostname : "(unknown)");

	snprintf(key_string[1], sizeof(key_string[1]), "x_%s_ProcessDescription", attribute);
	loginTableEntries[1].key = amqp_cstring_bytes(key_string[1]);
	loginTableEntries[1].value.kind = AMQP_FIELD_KIND_BYTES;
	loginTableEntries[1].value.value.bytes = amqp_cstring_bytes("FreeSwitch");

	snprintf(key_string[2], sizeof(key_string[2]), "x_%s_ProcessType", attribute);
	loginTableEntries[2].key = amqp_cstring_bytes(key_string[2]);
	loginTableEntries[2].value.kind = AMQP_FIELD_KIND_BYTES;
	loginTableEntries[2].value.value.bytes = amqp_cstring_bytes("TAP");

	snprintf(key_string[3], sizeof(key_string[3]), "x_%s_ProcessBuildVersion", attribute);
	loginTableEntries[3].key = amqp_cstring_bytes(key_string[3]);
	loginTableEntries[3].value.kind = AMQP_FIELD_KIND_BYTES;
	loginTableEntries[3].value.value.bytes = amqp_cstring_bytes(switch_version_full());

	snprintf(key_string[4], sizeof(key_string[4]), "x_%s_Liquid_ProcessBuildBornOn", attribute);
	loginTableEntries[4].key = amqp_cstring_bytes(key_string[4]);
	loginTableEntries[4].value.kind = AMQP_FIELD_KIND_BYTES;
	loginTableEntries[4].value.value.bytes = amqp_cstring_bytes(__DATE__ " " __TIME__);

	if (active) *active = NULL;
	for (connection_attempt = connections; connection_attempt; connection_attempt = connection_attempt->next) {
		if (mod_amqp_io_stopped(io)) goto err;
		mod_amqp_io_state(io, MOD_AMQP_IO_CONNECTING, NULL);
		mod_amqp_io_count(io, MOD_AMQP_CONNECT_ATTEMPTS);
		newConnection = amqp_new_connection();
		if (!newConnection) goto err;
		connect_timeout.tv_sec = connection_attempt->connect_timeout_ms / 1000;
		connect_timeout.tv_usec = (connection_attempt->connect_timeout_ms % 1000) * 1000;
		rpc_timeout.tv_sec = connection_attempt->rpc_timeout_ms / 1000;
		rpc_timeout.tv_usec = (connection_attempt->rpc_timeout_ms % 1000) * 1000;
		if (amqp_set_handshake_timeout(newConnection, &connect_timeout) != AMQP_STATUS_OK ||
			amqp_set_rpc_timeout(newConnection, &rpc_timeout) != AMQP_STATUS_OK) goto err;
		if (connection_attempt->ssl_on) {
			socket = amqp_ssl_socket_new(newConnection);
			if (socket) amqp_ssl_socket_set_verify_peer(socket, connection_attempt->ssl_verify_peer);
		} else {
			socket = amqp_tcp_socket_new(newConnection);
		}
		if (!socket) goto err;
		amqp_status = amqp_socket_open_noblock(socket, connection_attempt->hostname, connection_attempt->port, &connect_timeout);
		if (amqp_status == AMQP_STATUS_OK) break;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
			"Profile[%s] socket connection failed: %s\n", profile_name, amqp_error_string2(amqp_status));
		mod_amqp_io_count(io, MOD_AMQP_CONNECT_FAILURES);
		mod_amqp_io_state(io, MOD_AMQP_IO_DISCONNECTED, "socket_open");
		amqp_destroy_connection(newConnection);
		newConnection = NULL;
	}
	if (!connection_attempt) {
		phase = NULL; /* Each failed target was already counted. */
		goto err;
	}
	if (mod_amqp_io_stopped(io)) goto err;
	if (mod_amqp_io_register(io, amqp_get_sockfd(newConnection)) != SWITCH_STATUS_SUCCESS) goto err;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Profile[%s] opened socket connection to AMQP broker %s:%d\n",
					  profile_name, connection_attempt->hostname, connection_attempt->port);

	phase = "login";
	/* We have a connection, now log in */
	status = amqp_login_with_properties(newConnection,
										connection_attempt->virtualhost,
										channel_max,
										frame_max,
										connection_attempt->heartbeat,
										&loginProperties,
										AMQP_SASL_METHOD_PLAIN,
										connection_attempt->username,
										connection_attempt->password);

	if (mod_amqp_log_if_amqp_error(status, "Logging in")) goto err;
	if (mod_amqp_io_stopped(io)) goto err;
	phase = "channel_open";
	amqp_channel_open(newConnection, 1);
	if (mod_amqp_log_if_amqp_error(amqp_get_rpc_reply(newConnection), "Opening channel")) goto err;
	connection_attempt->state = newConnection;
	connection_attempt->io = io;
	if (active) *active = connection_attempt;

	return SWITCH_STATUS_SUCCESS;

err:
	if (phase && !mod_amqp_io_stopped(io)) {
		mod_amqp_io_count(io, MOD_AMQP_CONNECT_FAILURES);
		mod_amqp_io_state(io, MOD_AMQP_IO_DISCONNECTED, phase);
	}
	mod_amqp_io_release(io);
    if (newConnection) {
        amqp_destroy_connection(newConnection);
    }
    return SWITCH_STATUS_GENERR;
}

switch_status_t mod_amqp_connection_parse(mod_amqp_connection_t *new_con, switch_xml_t cfg, switch_memory_pool_t *pool)
{
	switch_xml_t param;
	char *name = (char *) switch_xml_attr_soft(cfg, "name");
	char *hostname = NULL, *virtualhost = NULL, *username = NULL, *password = NULL;
	unsigned int port = 0, heartbeat = 0;
	amqp_boolean_t ssl_on = 0;
	amqp_boolean_t ssl_verify_peer = 1;

	if (zstr(name)) {
		/* A connection XML dump may contain credentials. */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Connection missing name attribute\n");

		return SWITCH_STATUS_GENERR;
	}

	new_con->name = switch_core_strdup(pool, name);
	new_con->state = NULL;
	new_con->io = NULL;
	new_con->connect_timeout_ms = 3000;
	new_con->rpc_timeout_ms = 3000;
	new_con->next = NULL;

	for (param = switch_xml_child(cfg, "param"); param; param = param->next) {
		char *var = (char *) switch_xml_attr_soft(param, "name");
		char *val = (char *) switch_xml_attr_soft(param, "value");

		if (!var) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "AMQP connection[%s] param missing 'name' attribute\n", name);
			continue;
		}

		if (!val) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "AMQP connection[%s] param[%s] missing 'value' attribute\n", name, var);
			continue;
		}

		if (!strcmp(var, "connect-timeout-ms") || !strcmp(var, "rpc-timeout-ms")) {
			char *end = NULL;
			long timeout = strtol(val, &end, 10);
			if (end == val || *end || timeout < 1 || timeout > 60000) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid AMQP connection timeout (expected 1..60000 ms)\n");
				return SWITCH_STATUS_GENERR;
			}
			if (!strcmp(var, "connect-timeout-ms")) new_con->connect_timeout_ms = (unsigned int)timeout;
			else new_con->rpc_timeout_ms = (unsigned int)timeout;
		} else if (!strncmp(var, "hostname", 8)) {
			hostname = switch_core_strdup(pool, val);
		} else if (!strncmp(var, "virtualhost", 11)) {
			virtualhost = switch_core_strdup(pool, val);
		} else if (!strncmp(var, "username", 8)) {
			username = switch_core_strdup(pool, val);
		} else if (!strncmp(var, "password", 8)) {
			password = switch_core_strdup(pool, val);
		} else if (!strncmp(var, "port", 4)) {
			int interval = atoi(val);
			if (interval && interval > 0) {
				port = interval;
			}
		} else if (!strncmp(var, "heartbeat", 9)) {
			int interval = atoi(val);
			if (interval && interval > 0) {
				heartbeat = interval;
			}
		} else if (!strncmp(var, "ssl_on", 3) && switch_true(val) == SWITCH_TRUE) {
			ssl_on = 1;
		} else if (!strncmp(var, "ssl_verify_peer", 15) && switch_true(val) == SWITCH_FALSE) {
			ssl_verify_peer = 0;
		}
	}

	new_con->hostname = hostname ? hostname : "localhost";
	new_con->virtualhost = virtualhost ? virtualhost : "/";
	new_con->username = username ? username : "guest";
	new_con->password = password ? password : "guest";
	new_con->port = port ? port : 5672;
	new_con->heartbeat = heartbeat ? heartbeat : 0;
	new_con->ssl_on = ssl_on;
	new_con->ssl_verify_peer = ssl_verify_peer;

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t mod_amqp_connection_create(mod_amqp_connection_t **conn, switch_xml_t cfg, switch_memory_pool_t *pool)
{
	mod_amqp_connection_t *config = switch_core_alloc(pool, sizeof(*config));
	switch_status_t status = mod_amqp_connection_parse(config, cfg, pool);
	if (status == SWITCH_STATUS_SUCCESS) *conn = config;
	return status;
}

void mod_amqp_connection_destroy(mod_amqp_connection_t **conn)
{
	if (conn && *conn) {
		mod_amqp_connection_close(*conn);
		*conn = NULL;
	}
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
