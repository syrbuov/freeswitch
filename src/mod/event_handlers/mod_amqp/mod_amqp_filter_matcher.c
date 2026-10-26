#include "mod_amqp_filter_internal.h"

static int amqp_filter_condition_matches(const amqp_filter_condition_t *condition, const switch_event_t *event)
{
	const switch_event_header_t *header;
	if (condition->kind == AMQP_FILTER_SUBCLASS) {
		return event->subclass_name && !strcmp(event->subclass_name, condition->value);
	}
	for (header = event->headers; header; header = header->next) {
		int i;
		if (!header->name || !amqp_filter_field_equal(header->name, condition->field)) continue;
		if (header->idx > 0) {
			/* value is a cached ARRAY:: rendering, not a logical array element. */
			if (header->array) {
				for (i = 0; i < header->idx; i++) {
					if (header->array[i] && !strcmp(header->array[i], condition->value)) return 1;
				}
			}
		} else if (header->value && !strcmp(header->value, condition->value)) {
			return 1;
		}
	}
	return 0;
}

static int amqp_filter_bucket_matches(const amqp_filter_bucket_t *bucket, const switch_event_t *event)
{
	size_t r, c;
	for (r = 0; r < bucket->count; r++) {
		const amqp_filter_rule_t *rule = bucket->rules[r];
		for (c = 0; c < rule->condition_count; c++) {
			if (!amqp_filter_condition_matches(&rule->conditions[c], event)) break;
		}
		if (c == rule->condition_count) return 1;
	}
	return 0;
}

switch_bool_t mod_amqp_filter_match(const mod_amqp_filter_engine_t *engine, const switch_event_t *event)
{
	if (!engine || !event || (unsigned int) event->event_id > (unsigned int) SWITCH_EVENT_ALL) return SWITCH_FALSE;
	if (event->event_id != SWITCH_EVENT_ALL && amqp_filter_bucket_matches(&engine->buckets[event->event_id], event)) {
		return SWITCH_TRUE;
	}
	return amqp_filter_bucket_matches(&engine->buckets[SWITCH_EVENT_ALL], event) ? SWITCH_TRUE : SWITCH_FALSE;
}
