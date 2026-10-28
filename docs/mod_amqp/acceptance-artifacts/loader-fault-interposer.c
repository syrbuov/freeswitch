/* Acceptance-only fixture: fail exactly one producer event unbind. */
#include <switch.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <string.h>

static atomic_int fail_next_unbind;
static atomic_int failed_unbinds;
static atomic_int fail_all_unbinds;
static atomic_int fail_amqp_bind_at;
static atomic_int amqp_bind_calls;
static atomic_int amqp_deliveries;
static switch_event_callback_t amqp_callback;

void amqp_acceptance_fail_next_unbind(void)
{
	atomic_store(&fail_next_unbind, 1);
}

void amqp_acceptance_fail_all_unbinds(void)
{
	atomic_store(&fail_all_unbinds, 1);
}

void amqp_acceptance_fail_amqp_bind_at(int ordinal)
{
	atomic_store(&fail_amqp_bind_at, ordinal);
}

int amqp_acceptance_failed_unbinds(void)
{
	return atomic_load(&failed_unbinds);
}

int amqp_acceptance_bind_calls(void)
{
	return atomic_load(&amqp_bind_calls);
}

int amqp_acceptance_deliveries(void)
{
	return atomic_load(&amqp_deliveries);
}

static void amqp_acceptance_callback(switch_event_t *event)
{
	if (event->event_id == SWITCH_EVENT_DTMF && switch_event_get_header(event, "AMQP-Harness")) {
		atomic_fetch_add(&amqp_deliveries, 1);
	}
	amqp_callback(event);
}

SWITCH_DECLARE(switch_status_t) switch_event_unbind(switch_event_node_t **node)
{
	void *symbol;
	switch_status_t (*next_unbind)(switch_event_node_t **);
    if (atomic_load(&fail_all_unbinds) || atomic_exchange(&fail_next_unbind, 0)) {
		atomic_fetch_add(&failed_unbinds, 1);
		return SWITCH_STATUS_GENERR;
	}
	symbol = dlsym(RTLD_NEXT, "switch_event_unbind");
	if (!symbol) return SWITCH_STATUS_GENERR;
	memcpy(&next_unbind, &symbol, sizeof(next_unbind));
	return next_unbind(node);
}

SWITCH_DECLARE(switch_status_t) switch_event_bind_removable(const char *id,
	switch_event_types_t event, const char *subclass_name,
	switch_event_callback_t callback, void *user_data, switch_event_node_t **node)
{
	void *symbol;
	switch_status_t (*next_bind)(const char *, switch_event_types_t, const char *,
		switch_event_callback_t, void *, switch_event_node_t **);
	if (id && !strcmp(id, "AMQP") &&
		atomic_fetch_add(&amqp_bind_calls, 1) + 1 == atomic_load(&fail_amqp_bind_at)) {
		if (node) *node = NULL;
		return SWITCH_STATUS_GENERR;
	}
	if (id && !strcmp(id, "AMQP")) {
		amqp_callback = callback;
		callback = amqp_acceptance_callback;
	}
	symbol = dlsym(RTLD_NEXT, "switch_event_bind_removable");
	if (!symbol) return SWITCH_STATUS_GENERR;
	memcpy(&next_bind, &symbol, sizeof(next_bind));
	return next_bind(id, event, subclass_name, callback, user_data, node);
}
