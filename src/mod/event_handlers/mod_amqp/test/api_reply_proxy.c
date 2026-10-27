/* Register the integration executable's production amqp_reload with the real
 * Core API registry. This DSO runs only in the isolated test process. */
#include <switch.h>

typedef switch_status_t (*api_reply_handler_t)(const char *, switch_core_session_t *, switch_stream_handle_t *);
static api_reply_handler_t handler;

SWITCH_MODULE_LOAD_FUNCTION(mod_amqp_api_reply_proxy_load);
SWITCH_MODULE_DEFINITION(mod_amqp_api_reply_proxy, mod_amqp_api_reply_proxy_load, NULL, NULL);

SWITCH_MOD_DECLARE(void) mod_amqp_api_reply_proxy_set_handler(api_reply_handler_t callback)
{
	handler = callback;
}

SWITCH_STANDARD_API(api_reply_proxy_reload)
{
	return handler ? handler(cmd, session, stream) : SWITCH_STATUS_GENERR;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_amqp_api_reply_proxy_load)
{
	switch_api_interface_t *api_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	SWITCH_ADD_API(api_interface, "amqp", "isolated mod_amqp API reply test", api_reply_proxy_reload, "syntax");
	return SWITCH_STATUS_SUCCESS;
}
