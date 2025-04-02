/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2013, Anthony Minessale II <anthm@freeswitch.org>
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
 * Contributor(s):
 *
 * Brian West <brian@freeswitch.org>
 * Christopher Rienzo <chris.rienzo@grasshopper.com>
 * Nickolay V. Shmyrev <nshmyrev@alphacephei.com>
 *
 * mod_speechkit - Speech synthesis and recognition using MTT SpeechKit API.
 *
 *
 */

#define __PRETTY_FUNCTION__ __func__
#include <switch.h>
#include <netinet/tcp.h>
#include <libks/ks.h>


#define AUDIO_BLOCK_SIZE 3200

SWITCH_MODULE_LOAD_FUNCTION(mod_speechkit_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_speechkit_shutdown);
SWITCH_MODULE_DEFINITION(mod_speechkit, mod_speechkit_load, mod_speechkit_shutdown, NULL);

static switch_mutex_t *MUTEX = NULL;
static switch_event_node_t *NODE = NULL;

static struct {
	char *asr_server_url;
	int asr_return_json;

	char *tts_server_url;
	int auto_reload;
	switch_memory_pool_t *pool;
	ks_pool_t *ks_pool;
} globals;


typedef struct {
	kws_t *ws;
	ks_json_t *tts_params;
	switch_mutex_t *mutex;
	switch_buffer_t *audio_buffer;
} speechkit_tts_t;

typedef struct {
	kws_t *ws;
	ks_json_t *asr_params;
	char *result;
	switch_mutex_t *mutex;
	switch_buffer_t *audio_buffer;
} speechkit_asr_t;

/*! function to open the tts interface */
static switch_status_t speechkit_speech_open(switch_speech_handle_t *sh, const char *voice_name, int rate, int channels, switch_speech_flag_t *flags)
{
	speechkit_tts_t *speechkit;
	ks_json_t *req = ks_json_create_object();
	ks_json_add_string_to_object(req, "url", globals.tts_server_url);

	if (!(speechkit = (speechkit_tts_t *) switch_core_alloc(sh->memory_pool, sizeof(*speechkit)))) {
		return SWITCH_STATUS_MEMERR;
	}
	sh->private_info = speechkit;

	if (switch_buffer_create_dynamic(&speechkit->audio_buffer, AUDIO_BLOCK_SIZE, AUDIO_BLOCK_SIZE, 0) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Buffer create failed\n");
		return SWITCH_STATUS_MEMERR;
	}

	sh->native_rate = 16000;

	if (!voice_name) {voice_name = "Jane";};


	if (kws_connect_ex(&speechkit->ws, req, KWS_BLOCK | KWS_CLOSE_SOCK, globals.ks_pool, NULL, 30000) != KS_STATUS_SUCCESS) {
		ks_json_delete(&req);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Websocket connect to %s failed\n", globals.tts_server_url);
		return SWITCH_STATUS_GENERR;
	}
	ks_json_delete(&req);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Speechkit open\n");

	return SWITCH_STATUS_SUCCESS;
}

/*! function to close the tts interface */
static switch_status_t speechkit_speech_close(switch_speech_handle_t *sh, switch_speech_flag_t *flags)
{
	speechkit_tts_t *speechkit = (speechkit_tts_t *) sh->private_info;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Speechkit closed\n");

	/** FIXME: websockets server still expects us to read the close confirmation and only then close
	    libks library doens't implement it yet. */
		kws_close(speechkit->ws, KWS_CLOSE_SOCK);
		kws_destroy(&speechkit->ws);

	if (speechkit->audio_buffer) {
		switch_buffer_destroy(&speechkit->audio_buffer);
	}


	return SWITCH_STATUS_SUCCESS;
}

/*! function to feed text to the TTS */
static switch_status_t speechkit_speech_feed_tts(switch_speech_handle_t *sh, char *text, switch_speech_flag_t *flags)
{
	speechkit_tts_t *speechkit = (speechkit_tts_t *) sh->private_info;

	ks_json_t *tts_data = ks_json_create_object();
	ks_json_add_string_to_object(tts_data, "text", text);

	if (speechkit->tts_params) {
		ks_json_add_item_to_object(tts_data, "tts_params", speechkit->tts_params);
	}


	kws_write_frame(speechkit->ws, WSOC_TEXT, ks_json_print(tts_data), strlen(ks_json_print(tts_data)));

	ks_json_delete(&tts_data);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t speechkit_speech_read_tts(switch_speech_handle_t *sh, void *data, switch_size_t *datalen, switch_speech_flag_t *flags)
{	
	int poll_result;
	kws_opcode_t oc;
	uint8_t *rdata;
	int rlen;
	size_t bytes_read;
	speechkit_tts_t *speechkit = (speechkit_tts_t *) sh->private_info;
	
	poll_result = kws_wait_sock(speechkit->ws, 0, KS_POLL_READ | KS_POLL_ERROR);
	if (poll_result != KS_POLL_READ) {
		return SWITCH_STATUS_SUCCESS;
	}
	rlen = kws_read_frame(speechkit->ws, &oc, &rdata);
	if (rlen < 0) {
		return SWITCH_STATUS_BREAK;
	}
	if (oc == WSOC_PING) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Received ping\n");
		kws_write_frame(speechkit->ws, WSOC_PONG, rdata, rlen);
		return SWITCH_STATUS_SUCCESS;
	}

	switch_buffer_write(speechkit->audio_buffer, rdata, rlen);

	if ((bytes_read = switch_buffer_read(speechkit->audio_buffer, data, *datalen))) {
		*datalen = bytes_read;
		return SWITCH_STATUS_SUCCESS;
	}

	return SWITCH_STATUS_FALSE;
}

static void speechkit_speech_flush_tts(switch_speech_handle_t *sh)
{
}

static void speechkit_text_param_tts(switch_speech_handle_t *sh, char *param, const char *val)
{
	speechkit_tts_t *speechkit = (speechkit_tts_t *) sh->private_info;
	if (!speechkit->tts_params) {
		speechkit->tts_params = ks_json_create_object();
		ks_json_add_string_to_object(speechkit->tts_params, param, val);
	} else {
		if (!zstr(param) && !zstr(val)) {
			ks_json_add_string_to_object(speechkit->tts_params, param, val);
		}
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "TTS params %s: %s\n", param, val);

}

static void speechkit_numeric_param_tts(switch_speech_handle_t *sh, char *param, int val)
{
}

static void speechkit_float_param_tts(switch_speech_handle_t *sh, char *param, double val)
{
}

/*! function to open the asr interface */
static switch_status_t speechkit_asr_open(switch_asr_handle_t *ah, const char *codec, int rate, const char *dest, switch_asr_flag_t *flags)
{
	speechkit_asr_t *speechkit;
	ks_json_t *req = ks_json_create_object();
	ks_json_add_string_to_object(req, "url", (dest ? dest : globals.asr_server_url));

	if (!(speechkit = (speechkit_asr_t *) switch_core_alloc(ah->memory_pool, sizeof(*speechkit)))) {
		return SWITCH_STATUS_MEMERR;
	}

	
	ah->private_info = speechkit;
	switch_mutex_init(&speechkit->mutex, SWITCH_MUTEX_NESTED, ah->memory_pool);

	if (switch_buffer_create_dynamic(&speechkit->audio_buffer, AUDIO_BLOCK_SIZE, AUDIO_BLOCK_SIZE, 0) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Buffer create failed\n");
		return SWITCH_STATUS_MEMERR;
	}

	codec = "L16";
	ah->codec = switch_core_strdup(ah->memory_pool, codec);

	if (kws_connect_ex(&speechkit->ws, req, KWS_BLOCK | KWS_CLOSE_SOCK, globals.ks_pool, NULL, 30000) != KS_STATUS_SUCCESS) {
		ks_json_delete(&req);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Websocket connect to %s failed\n", globals.asr_server_url);
		return SWITCH_STATUS_GENERR;
	}
	ks_json_delete(&req);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ASR open\n");

	return SWITCH_STATUS_SUCCESS;
}

/*! function to close the asr interface */
static switch_status_t speechkit_asr_close(switch_asr_handle_t *ah, switch_asr_flag_t *flags)
{
	speechkit_asr_t *speechkit = (speechkit_asr_t *) ah->private_info;

	switch_mutex_lock(speechkit->mutex);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ASR closed\n");

	/** FIXME: websockets server still expects us to read the close confirmation and only then close
	    libks library doens't implement it yet. */
	kws_close(speechkit->ws, KWS_CLOSE_SOCK);
	kws_destroy(&speechkit->ws);

	switch_set_flag(ah, SWITCH_ASR_FLAG_CLOSED);
	switch_buffer_destroy(&speechkit->audio_buffer);
	switch_safe_free(speechkit->result);
	switch_mutex_unlock(speechkit->mutex);

	return SWITCH_STATUS_SUCCESS;
}

/*! function to feed audio to the ASR */
static switch_status_t speechkit_asr_feed(switch_asr_handle_t *ah, void *data, unsigned int len, switch_asr_flag_t *flags)
{
	int poll_result;
	kws_opcode_t oc;
	uint8_t *rdata;
	int rlen;
	speechkit_asr_t *speechkit = (speechkit_asr_t *) ah->private_info;

	if (switch_test_flag(ah, SWITCH_ASR_FLAG_CLOSED))
		return SWITCH_STATUS_BREAK;

	switch_mutex_lock(speechkit->mutex);

	switch_buffer_write(speechkit->audio_buffer, data, len);
	if (switch_buffer_inuse(speechkit->audio_buffer) > AUDIO_BLOCK_SIZE) {
		char buf[AUDIO_BLOCK_SIZE];
		int rlen;

		rlen = switch_buffer_read(speechkit->audio_buffer, buf, AUDIO_BLOCK_SIZE);
		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Sending data %d\n", rlen);
		if (kws_write_frame(speechkit->ws, WSOC_BINARY, buf, rlen) < 0) {
			switch_mutex_unlock(speechkit->mutex);
			return SWITCH_STATUS_BREAK;
		}
	}

	poll_result = kws_wait_sock(speechkit->ws, 0, KS_POLL_READ | KS_POLL_ERROR);
	if (poll_result != KS_POLL_READ) {
		switch_mutex_unlock(speechkit->mutex);
		return SWITCH_STATUS_SUCCESS;
	}
	rlen = kws_read_frame(speechkit->ws, &oc, &rdata);
	if (rlen < 0) {
		switch_mutex_unlock(speechkit->mutex);
		return SWITCH_STATUS_BREAK;
	}
	if (oc == WSOC_PING) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Received ping\n");
		kws_write_frame(speechkit->ws, WSOC_PONG, rdata, rlen);
		switch_mutex_unlock(speechkit->mutex);
		return SWITCH_STATUS_SUCCESS;
	}

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Received %d bytes:\n%s\n", rlen, rdata);
	switch_safe_free(speechkit->result);
	speechkit->result = switch_safe_strdup((const char *)rdata);
	switch_mutex_unlock(speechkit->mutex);

	return SWITCH_STATUS_SUCCESS;
}

/*! function to pause recognizer */
static switch_status_t speechkit_asr_pause(switch_asr_handle_t *ah)
{
	return SWITCH_STATUS_SUCCESS;
}

/*! function to resume recognizer */
static switch_status_t speechkit_asr_resume(switch_asr_handle_t *ah)
{
	return SWITCH_STATUS_SUCCESS;
}

/*! Process asr_load_grammar request from FreeSWITCH. */
static switch_status_t speechkit_asr_load_grammar(switch_asr_handle_t *ah, const char *grammar, const char *name)
{
	return SWITCH_STATUS_SUCCESS;
}

/*! Process asr_unload_grammar request from FreeSWITCH. */
static switch_status_t speechkit_asr_unload_grammar(switch_asr_handle_t *ah, const char *name)
{
	return SWITCH_STATUS_SUCCESS;
}


/*! function to read results from the ASR*/
static switch_status_t speechkit_asr_check_results(switch_asr_handle_t *ah, switch_asr_flag_t *flags)
{
	speechkit_asr_t *speechkit = (speechkit_asr_t *) ah->private_info;
	return (speechkit->result && (strstr(speechkit->result, "\"\"") == NULL)) ? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}

/*! function to read results from the ASR */
static switch_status_t speechkit_asr_get_results(switch_asr_handle_t *ah, char **xmlstr, switch_asr_flag_t *flags)
{
	speechkit_asr_t *speechkit = (speechkit_asr_t *) ah->private_info;
	switch_status_t ret;


	switch_mutex_lock(speechkit->mutex);
	if (globals.asr_return_json) {
		if  (strstr(speechkit->result, "\"partial\"") == NULL) {
			*xmlstr = switch_safe_strdup(speechkit->result);
			ret = SWITCH_STATUS_SUCCESS;
		} else {
			*xmlstr = switch_safe_strdup(speechkit->result);
			ret = SWITCH_STATUS_MORE_DATA;
		}
	} else {
		cJSON *result = cJSON_Parse(speechkit->result);

		if (cJSON_HasObjectItem(result, "text")) {
			*xmlstr = switch_safe_strdup(cJSON_GetObjectCstr(result, "text"));
			ret = SWITCH_STATUS_SUCCESS;
		} else if (cJSON_HasObjectItem(result, "partial")) {
			*xmlstr = switch_safe_strdup(cJSON_GetObjectCstr(result, "partial"));
			ret = SWITCH_STATUS_MORE_DATA;
		} else {
			ret = SWITCH_STATUS_GENERR;
		}
		cJSON_Delete(result);
	}

	switch_safe_free(speechkit->result);
	speechkit->result = NULL;
	switch_mutex_unlock(speechkit->mutex);

	return ret;
}

/*! function to get text params */
static void speechkit_asr_text_param(switch_asr_handle_t *ah, char *param, const char *val) 
{
	speechkit_asr_t *speechkit = (speechkit_asr_t *) ah->private_info;
	if (!speechkit->asr_params) {
		speechkit->asr_params = ks_json_create_object();
		ks_json_add_string_to_object(speechkit->asr_params, param, val);
	} else {
		if (!zstr(param) && !zstr(val)) {
			ks_json_add_string_to_object(speechkit->asr_params, param, val);
		}
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ASR params %s: %s\n", param, val);	
}

/*! function to start input timeouts */
static switch_status_t speechkit_asr_start_input_timers(switch_asr_handle_t *ah)
{
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t load_config(void)
{
	char *cf = "speechkit.conf";
	switch_xml_t cfg, xml = NULL, param, settings;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		status = SWITCH_STATUS_FALSE;
		goto done;
	}


	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			if (!strcasecmp(var, "tts-server-url")) {
				globals.tts_server_url = switch_core_strdup(globals.pool, val);
			}
			if (!strcasecmp(var, "asr-server-url")) {
				globals.asr_server_url = switch_core_strdup(globals.pool, val);
			}
			if (!strcasecmp(var, "asr-return-json")) {
				globals.asr_return_json = atoi(val);
			}
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ASR-TTS-URLs: %s %s\n", globals.asr_server_url, globals.tts_server_url);
	}

  done:
	if (!globals.tts_server_url) {
		globals.tts_server_url = switch_core_strdup(globals.pool, "ws://127.0.0.1/tts:2700");
	}
	if (!globals.asr_server_url) {
		globals.asr_server_url = switch_core_strdup(globals.pool, "ws://127.0.0.1/asr:2700");
	}
	if (xml) {
		switch_xml_free(xml);
	}

	return status;
}

static void do_load(void)
{
	switch_mutex_lock(MUTEX);
	load_config();
	switch_mutex_unlock(MUTEX);
}

static void event_handler(switch_event_t *event)
{
	if (globals.auto_reload) {
		do_load();
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "speechkit Reloaded\n");
	}
}

SWITCH_MODULE_LOAD_FUNCTION(mod_speechkit_load)
{
	switch_speech_interface_t *speech_interface;
	switch_asr_interface_t *asr_interface;

	switch_mutex_init(&MUTEX, SWITCH_MUTEX_NESTED, pool);

	globals.pool = pool;

	ks_init();

	ks_pool_open(&globals.ks_pool);
	// ks_global_set_default_logger(7);
	ks_global_set_log_level(7);

	if ((switch_event_bind_removable(modname, SWITCH_EVENT_RELOADXML, NULL, event_handler, NULL, &NODE) != SWITCH_STATUS_SUCCESS)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind!\n");
	}

	do_load();

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	speech_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_SPEECH_INTERFACE);
	speech_interface->interface_name = "speechkit";
	speech_interface->speech_open = speechkit_speech_open;
	speech_interface->speech_close = speechkit_speech_close;
	speech_interface->speech_feed_tts = speechkit_speech_feed_tts;
	speech_interface->speech_read_tts = speechkit_speech_read_tts;
	speech_interface->speech_flush_tts = speechkit_speech_flush_tts;
	speech_interface->speech_text_param_tts = speechkit_text_param_tts;
	speech_interface->speech_numeric_param_tts = speechkit_numeric_param_tts;
	speech_interface->speech_float_param_tts = speechkit_float_param_tts;

	asr_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_ASR_INTERFACE);
	asr_interface->interface_name = "speechkit";
	asr_interface->asr_open = speechkit_asr_open;
	asr_interface->asr_close = speechkit_asr_close;
	asr_interface->asr_load_grammar = speechkit_asr_load_grammar;
	asr_interface->asr_unload_grammar = speechkit_asr_unload_grammar;
	asr_interface->asr_resume = speechkit_asr_resume;
	asr_interface->asr_pause = speechkit_asr_pause;
	asr_interface->asr_feed = speechkit_asr_feed;
	asr_interface->asr_check_results = speechkit_asr_check_results;
	asr_interface->asr_get_results = speechkit_asr_get_results;
	asr_interface->asr_start_input_timers = speechkit_asr_start_input_timers;
	asr_interface->asr_text_param = speechkit_asr_text_param;

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_speechkit_shutdown)
{
	ks_pool_close(&globals.ks_pool);
	ks_shutdown();

	switch_event_unbind(&NODE);
	return SWITCH_STATUS_UNLOAD;
}


/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
