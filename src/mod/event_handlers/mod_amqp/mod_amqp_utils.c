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

int mod_amqp_log_if_amqp_error(amqp_rpc_reply_t x, char const *context)
{
	switch (x.reply_type) {
	case AMQP_RESPONSE_NORMAL:
		return 0;

	case AMQP_RESPONSE_NONE:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s: missing RPC reply type!\n", context);
		break;

	case AMQP_RESPONSE_LIBRARY_EXCEPTION:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s: %s\n", context, amqp_error_string2(x.library_error));
		break;

	case AMQP_RESPONSE_SERVER_EXCEPTION:
		switch (x.reply.id) {
		case AMQP_CONNECTION_CLOSE_METHOD: {
			amqp_connection_close_t *m = (amqp_connection_close_t *) x.reply.decoded;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s: server connection error %d, message: %.*s\n",
							  context, m->reply_code, (int) m->reply_text.len, (char *) m->reply_text.bytes);
			break;
		}
		case AMQP_CHANNEL_CLOSE_METHOD: {
			amqp_channel_close_t *m = (amqp_channel_close_t *) x.reply.decoded;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s: server channel error %d, message: %.*s\n",
							  context, m->reply_code, (int) m->reply_text.len, (char *) m->reply_text.bytes);
			break;
		}
		default:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s: unknown server error, method id 0x%08X\n", context, x.reply.id);
			break;
		}
		break;

	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s: unknown reply_type: %d \n", context, x.reply_type);
			break;
	}

	return -1;
}

int mod_amqp_count_chars(const char* string, char ch)
{
	int c = 0;
	while (*string) c += *(string++) == ch;
	return c;
}

/* Called with lifecycle_mutex held. A command worker must not join itself. */
switch_bool_t mod_amqp_is_command_thread(void)
{
	switch_hash_index_t *hi;
	mod_amqp_command_profile_t *profile;
	switch_bool_t current;

	for (hi = switch_core_hash_first(mod_amqp_globals.command_hash); hi; hi = switch_core_hash_next(&hi)) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&profile);
		switch_mutex_lock(profile->mutex);
		current = profile->command_thread_started && switch_thread_equal(profile->command_thread_id, switch_thread_self());
		switch_mutex_unlock(profile->mutex);
		if (current) {
			switch_safe_free(hi);
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/* All functions below run under lifecycle_mutex. List nodes outlive XML only
 * through their owned candidates; names are copied for duplicate validation. */
typedef struct amqp_prepared_item_s {
	char *name;
	mod_amqp_producer_prepared_t *prepared;
	struct amqp_prepared_item_s *next;
} amqp_prepared_item_t;

static void amqp_prepared_set_destroy(amqp_prepared_item_t **head)
{
	while (*head) {
		amqp_prepared_item_t *item = *head;
		*head = item->next;
		mod_amqp_producer_prepared_destroy(&item->prepared);
		free(item->name);
		free(item);
	}
}

static switch_status_t amqp_prepare_set(switch_xml_t cfg, amqp_prepared_item_t **head)
{
	switch_xml_t profiles = switch_xml_child(cfg, "producers"), xml;
	amqp_prepared_item_t **tail = head;
	for (xml = profiles ? switch_xml_child(profiles, "profile") : NULL; xml; xml = xml->next) {
		const char *name = switch_xml_attr_soft(xml, "name");
		amqp_prepared_item_t *item, *other;
		if (zstr(name)) return SWITCH_STATUS_GENERR;
		for (other = *head; other; other = other->next) {
			if (!strcmp(name, other->name)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Duplicate producer profile[%s]\n", name);
				return SWITCH_STATUS_GENERR;
			}
		}
		item = calloc(1, sizeof(*item));
		if (!item) return SWITCH_STATUS_MEMERR;
		*tail = item;
		tail = &item->next;
		item->name = strdup(name);
		if (!item->name || mod_amqp_producer_prepare(name, xml, &item->prepared) != SWITCH_STATUS_SUCCESS) return SWITCH_STATUS_GENERR;
	}
	return SWITCH_STATUS_SUCCESS;
}

/* Try every owner once when unwinding a newly activated set. Retained profiles
 * remain in the active hash, but must not cause an infinite first-entry loop. */
static switch_status_t amqp_destroy_producers(switch_bool_t stop_on_error)
{
	switch_hash_index_t *hi;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	for (hi = switch_core_hash_first(mod_amqp_globals.producer_hash); hi;) {
		mod_amqp_producer_profile_t *producer;
		switch_core_hash_this(hi, NULL, NULL, (void **)&producer);
		/* Advance before destroy deletes the current hashtable entry. */
		hi = switch_core_hash_next(&hi);
		if (mod_amqp_producer_destroy(&producer) != SWITCH_STATUS_SUCCESS) {
			status = SWITCH_STATUS_GENERR;
			if (stop_on_error) {
				switch_safe_free(hi);
				break;
			}
		}
	}
	return status;
}

switch_status_t mod_amqp_do_config(switch_bool_t reload)
{
	switch_xml_t cfg = NULL, xml = NULL, profiles, profile;
	switch_status_t status = SWITCH_STATUS_GENERR;
	amqp_prepared_item_t *prepared = NULL, *item;
	switch_hash_index_t *hi = NULL;
	switch_bool_t change_started = SWITCH_FALSE;
	switch_bool_t preparation_failed = SWITCH_FALSE;

	/* Never wait: teardown may be joining an AMQP command worker calling us. */
	if (switch_mutex_trylock(mod_amqp_globals.lifecycle_mutex) != SWITCH_STATUS_SUCCESS) return SWITCH_STATUS_GENERR;
	if (mod_amqp_globals.shutting_down || (reload && mod_amqp_is_command_thread())) goto done;
	if (!(xml = switch_xml_open_cfg("amqp.conf", &cfg, NULL))) {
		preparation_failed = SWITCH_TRUE;
		goto done;
	}
	/* This uses the existing XML snapshot. It does not invoke reloadxml. */
	if (amqp_prepare_set(cfg, &prepared) != SWITCH_STATUS_SUCCESS) {
		preparation_failed = SWITCH_TRUE;
		goto done;
	}

	if (reload) {
		/* No new bindings until ALL old producers have been destroyed. */
		change_started = SWITCH_TRUE;
		if (amqp_destroy_producers(SWITCH_TRUE) != SWITCH_STATUS_SUCCESS) goto done;
	} else if (!switch_core_hash_empty(mod_amqp_globals.producer_hash)) {
		goto done;
	}
	change_started = SWITCH_TRUE;
	for (item = prepared; item; item = item->next) {
		if (mod_amqp_producer_activate(item->prepared) != SWITCH_STATUS_SUCCESS) {
			/* No rollback of the old set. Cleanup includes the failed owner. */
			amqp_destroy_producers(SWITCH_FALSE);
			goto done;
		}
	}

	/* Adjacent profiles are not transactional. Only touch them after producer
	 * preparation and switching have succeeded; propagate their errors. */
	if (reload) {
		mod_amqp_command_profile_t *command;
		mod_amqp_logging_profile_t *logging;
		while ((hi = switch_core_hash_first_iter(mod_amqp_globals.command_hash, hi))) {
			switch_core_hash_this(hi, NULL, NULL, (void **)&command);
			if (mod_amqp_command_destroy(&command) != SWITCH_STATUS_SUCCESS) goto done;
		}
		if (mod_amqp_globals.logging_bound) {
			if (switch_log_unbind_logger(mod_amqp_logging_recv) != SWITCH_STATUS_SUCCESS) goto done;
			mod_amqp_globals.logging_bound = SWITCH_FALSE;
		}
		while ((hi = switch_core_hash_first_iter(mod_amqp_globals.logging_hash, hi))) {
			switch_core_hash_this(hi, NULL, NULL, (void **)&logging);
			if (mod_amqp_logging_destroy(&logging) != SWITCH_STATUS_SUCCESS) goto restore_logger;
		}
	}

	status = SWITCH_STATUS_SUCCESS;
	profiles = switch_xml_child(cfg, "commands");
	for (profile = profiles ? switch_xml_child(profiles, "profile") : NULL; profile; profile = profile->next) {
		/* Legacy executor restored for the trusted local test application.
		 * Production configurations must omit command profiles. */
		const char *name = switch_xml_attr_soft(profile, "name");
		if (zstr(name) || switch_core_hash_find(mod_amqp_globals.command_hash, name) ||
			mod_amqp_command_create((char *)name, profile) != SWITCH_STATUS_SUCCESS) status = SWITCH_STATUS_GENERR;
	}
	profiles = switch_xml_child(cfg, "logging");
	for (profile = profiles ? switch_xml_child(profiles, "profile") : NULL; profile; profile = profile->next) {
		const char *name = switch_xml_attr_soft(profile, "name");
		if (zstr(name) || switch_core_hash_find(mod_amqp_globals.logging_hash, name) ||
			mod_amqp_logging_create((char *)name, profile) != SWITCH_STATUS_SUCCESS) status = SWITCH_STATUS_GENERR;
	}
restore_logger:
	if (!mod_amqp_globals.logging_bound) {
		if (switch_log_bind_logger(mod_amqp_logging_recv, SWITCH_LOG_DEBUG, SWITCH_FALSE) == SWITCH_STATUS_SUCCESS) {
			mod_amqp_globals.logging_bound = SWITCH_TRUE;
		} else status = SWITCH_STATUS_GENERR;
	}
done:
	if (status == SWITCH_STATUS_SUCCESS) {
		mod_amqp_health_set(MOD_AMQP_HEALTH_ACTIVE, "configuration active");
	} else if (change_started) {
		mod_amqp_health_set(MOD_AMQP_HEALTH_DEGRADED,
			"configuration switch failed after teardown began; retry config reload or restart");
	} else if (preparation_failed) {
		/* Whatever runtime state existed before preparation remains unchanged. */
		mod_amqp_health_note("configuration preparation failed; existing runtime set unchanged");
	}
	switch_safe_free(hi);
	amqp_prepared_set_destroy(&prepared);
	if (xml) switch_xml_free(xml);
	switch_mutex_unlock(mod_amqp_globals.lifecycle_mutex);
	return status;
}


#define KEY_SAFE(C) ((C >= 'a' && C <= 'z') || \
					(C >= 'A' && C <= 'Z') || \
					(C >= '0' && C <= '9') || \
					(C == '-' || C == '~' || C == '_'))

switch_status_t amqp_util_encode(const char *key, char *dest, size_t capacity)
{
	static const char hex[] = "0123456789ABCDEF";
	const unsigned char *p = (const unsigned char *)key;
	size_t used = 0;
	if (!capacity) return SWITCH_STATUS_GENERR;
	dest[0] = '\0';
	if ((key[0] == '#' || key[0] == '*') && !key[1]) {
		if (capacity < 2) return SWITCH_STATUS_GENERR;
		dest[0] = key[0]; dest[1] = '\0';
		return SWITCH_STATUS_SUCCESS;
	}
	for (; *p; p++) {
		size_t bytes = (KEY_SAFE(*p) || *p == ' ') ? 1 : 3;
		if (bytes >= capacity - used) {
			dest[0] = '\0';
			return SWITCH_STATUS_GENERR;
		}
		if (KEY_SAFE(*p)) dest[used++] = (char)*p;
		else if (*p == ' ') dest[used++] = '+';
		else {
			dest[used++] = '%';
			dest[used++] = hex[*p >> 4];
			dest[used++] = hex[*p & 15];
		}
	}
	dest[used] = '\0';
	return SWITCH_STATUS_SUCCESS;
}

void mod_amqp_util_msg_destroy(mod_amqp_message_t **msg)
{
	if (!msg || !*msg) return;
	switch_safe_free((*msg)->pjson);
	switch_safe_free(*msg);
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
