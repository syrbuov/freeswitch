/* Fail the second AMQP event binding without changing successful callbacks. */
#include <switch.h>
#include <dlfcn.h>
#include <string.h>

static int amqp_binds;
static int individual_unbinds;
static int global_unbinds;
static int serialized_probe_events;

int probe_binds(void) { return amqp_binds; }
int probe_individual_unbinds(void) { return individual_unbinds; }
int probe_global_unbinds(void) { return global_unbinds; }
int probe_serialized_events(void) { return serialized_probe_events; }

SWITCH_DECLARE(switch_status_t) switch_event_serialize_json(switch_event_t *event, char **str)
{
	void *symbol = dlsym(RTLD_NEXT, "switch_event_serialize_json");
	switch_status_t (*next_serialize)(switch_event_t *, char **);
	if (event && event->event_id == SWITCH_EVENT_DTMF &&
		switch_event_get_header(event, "Probe-Origin")) serialized_probe_events++;
	if (!symbol) return SWITCH_STATUS_GENERR;
	memcpy(&next_serialize, &symbol, sizeof(next_serialize));
	return next_serialize(event, str);
}

SWITCH_DECLARE(switch_status_t) switch_event_bind_removable(const char *id,
	switch_event_types_t event, const char *subclass_name,
	switch_event_callback_t callback, void *user_data, switch_event_node_t **node)
{
	void *symbol = dlsym(RTLD_NEXT, "switch_event_bind_removable");
	switch_status_t (*next_bind)(const char *, switch_event_types_t, const char *,
		switch_event_callback_t, void *, switch_event_node_t **);
	if (id && !strcmp(id, "AMQP") && ++amqp_binds == 2) {
		if (node) *node = NULL;
		return SWITCH_STATUS_GENERR;
	}
	if (!symbol) return SWITCH_STATUS_GENERR;
	memcpy(&next_bind, &symbol, sizeof(next_bind));
	return next_bind(id, event, subclass_name, callback, user_data, node);
}

SWITCH_DECLARE(switch_status_t) switch_event_unbind(switch_event_node_t **node)
{
	void *symbol = dlsym(RTLD_NEXT, "switch_event_unbind");
	switch_status_t (*next_unbind)(switch_event_node_t **);
	individual_unbinds++;
	if (!symbol) return SWITCH_STATUS_GENERR;
	memcpy(&next_unbind, &symbol, sizeof(next_unbind));
	return next_unbind(node);
}

SWITCH_DECLARE(switch_status_t) switch_event_unbind_callback(switch_event_callback_t callback)
{
	void *symbol = dlsym(RTLD_NEXT, "switch_event_unbind_callback");
	switch_status_t (*next_unbind)(switch_event_callback_t);
	global_unbinds++;
	if (!symbol) return SWITCH_STATUS_GENERR;
	memcpy(&next_unbind, &symbol, sizeof(next_unbind));
	return next_unbind(callback);
}
