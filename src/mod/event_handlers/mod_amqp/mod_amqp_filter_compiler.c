#include "mod_amqp_filter_internal.h"

void mod_amqp_filter_engine_destroy(mod_amqp_filter_engine_t **handle)
{
	mod_amqp_filter_engine_t *engine;
	size_t r, c;
	if (!handle || !(engine = *handle)) return;
	if (engine->rules) {
		for (r = 0; r < engine->rule_count; r++) {
			amqp_filter_rule_t *rule = &engine->rules[r];
			if (rule->conditions) {
				for (c = 0; c < rule->condition_count; c++) {
					free(rule->conditions[c].field);
					free(rule->conditions[c].value);
				}
				free(rule->conditions);
			}
		}
		free(engine->rules);
	}
	free(engine->index_entries);
	free(engine);
	*handle = NULL;
}

/* Revalidation is independent of the source XML. An opaque DTO can only be
 * created by our parser, but keeping limits here makes compile's contract local.
 */
static mod_amqp_filter_status_t amqp_filter_validate_dto(const mod_amqp_filter_dto_t *dto,
	mod_amqp_filter_error_t *error)
{
	size_t r, c, total = 0, bytes;
	if (!dto || (dto->rule_count && !dto->rules)) {
		return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, 0, 0, 0, "Missing parser DTO or rules");
	}
	if (dto->rule_count > MOD_AMQP_FILTER_MAX_RULES) {
		return amqp_filter_error(error, MOD_AMQP_FILTER_LIMIT, 0, 0, 0, "Too many rules");
	}
	for (r = 0; r < dto->rule_count; r++) {
		const amqp_filter_dto_rule_t *rule = &dto->rules[r];
		int id, selected = 0;
		if (rule->condition_count > MOD_AMQP_FILTER_MAX_CONDITIONS) {
			return amqp_filter_error(error, MOD_AMQP_FILTER_LIMIT, r + 1, 0, 0, "Too many conditions");
		}
		if (rule->condition_count && !rule->conditions) {
			return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, r + 1, 0, 0, "Missing conditions");
		}
		for (id = 0; id < SWITCH_EVENT_ALL; id++) selected |= rule->selected[id];
		if ((!rule->any_event && !selected) || rule->selected[SWITCH_EVENT_ALL]) {
			return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, r + 1, 0, 0, "Invalid normalized selector");
		}
		for (c = 0; c < rule->condition_count; c++) {
			const amqp_filter_condition_t *condition = &rule->conditions[c];
			mod_amqp_filter_status_t status;
			status = amqp_filter_string_size(condition->field, MOD_AMQP_FILTER_MAX_FIELD_BYTES, &total, &bytes);
			if (status == MOD_AMQP_FILTER_OK) {
				status = amqp_filter_string_size(condition->value, MOD_AMQP_FILTER_MAX_VALUE_BYTES, &total, &bytes);
			}
			if (status != MOD_AMQP_FILTER_OK) {
				return amqp_filter_error(error, status, r + 1, 0, c + 1, "Missing or oversized field/value or string budget exceeded");
			}
			if (!*condition->field || amqp_filter_field_equal(condition->field, "Event-Name") ||
				amqp_filter_field_equal(condition->field, "_body") ||
				(condition->kind != AMQP_FILTER_HEADER && condition->kind != AMQP_FILTER_SUBCLASS) ||
				((condition->kind == AMQP_FILTER_SUBCLASS) != amqp_filter_field_equal(condition->field, "Event-Subclass"))) {
				return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, r + 1, 0, c + 1, "Invalid compiled condition field");
			}
		}
	}
	return MOD_AMQP_FILTER_OK;
}

mod_amqp_filter_status_t mod_amqp_filter_compile(const mod_amqp_filter_dto_t *dto,
	mod_amqp_filter_engine_t **out, mod_amqp_filter_error_t *error)
{
	mod_amqp_filter_engine_t *engine = NULL;
	mod_amqp_filter_status_t status;
	size_t r = 0, c = 0, bytes, total_refs = 0, offset = 0, error_rule = 0, error_condition = 0;
	size_t written[MOD_AMQP_FILTER_BUCKETS] = { 0 };
	int id;
	amqp_filter_error(error, MOD_AMQP_FILTER_OK, 0, 0, 0, "");
	if (!out) return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, 0, 0, 0, "Missing engine output");
	*out = NULL;
	status = amqp_filter_validate_dto(dto, error);
	if (status != MOD_AMQP_FILTER_OK) return status;
	if (!(engine = calloc(1, sizeof(*engine)))) goto nomem;
	engine->rule_count = dto->rule_count;
	if (!amqp_filter_mul_size(engine->rule_count, sizeof(*engine->rules), &bytes)) goto overflow;
	if (bytes && !(engine->rules = calloc(1, bytes))) goto nomem;
	for (r = 0; r < dto->rule_count; r++) {
		const amqp_filter_dto_rule_t *source = &dto->rules[r];
		amqp_filter_rule_t *dest = &engine->rules[r];
		error_rule = r + 1;
		dest->condition_count = source->condition_count;
		c = 0;
		if (!amqp_filter_mul_size(dest->condition_count, sizeof(*dest->conditions), &bytes)) goto overflow;
		if (bytes && !(dest->conditions = calloc(1, bytes))) goto nomem;
		for (c = 0; c < dest->condition_count; c++) {
			amqp_filter_condition_t *condition = &dest->conditions[c];
			error_condition = c + 1;
			condition->kind = source->conditions[c].kind;
			bytes = strlen(source->conditions[c].field) + 1;
			if (!(condition->field = malloc(bytes))) goto nomem;
			memcpy(condition->field, source->conditions[c].field, bytes);
			bytes = strlen(source->conditions[c].value) + 1;
			if (!(condition->value = malloc(bytes))) goto nomem;
			memcpy(condition->value, source->conditions[c].value, bytes);
			error_condition = 0;
		}
		for (id = 0; id <= SWITCH_EVENT_ALL; id++) {
			if ((source->any_event && id == SWITCH_EVENT_ALL) || (!source->any_event && source->selected[id])) {
				if (!amqp_filter_add_size(total_refs, 1, &total_refs)) goto overflow;
				engine->buckets[id].count++;
			}
		}
	}
	error_rule = 0;
	if (!amqp_filter_mul_size(total_refs, sizeof(*engine->index_entries), &bytes)) goto overflow;
	if (bytes && !(engine->index_entries = calloc(1, bytes))) goto nomem;
	for (id = 0; id <= SWITCH_EVENT_ALL; id++) {
		amqp_filter_bucket_t *bucket = &engine->buckets[id];
		if (bucket->count) {
			bucket->rules = engine->index_entries + offset;
			offset += bucket->count; /* Bounded by the checked total_refs sum. */
		}
	}
	for (r = 0; r < dto->rule_count; r++) {
		const amqp_filter_dto_rule_t *source = &dto->rules[r];
		for (id = 0; id <= SWITCH_EVENT_ALL; id++) {
			if ((source->any_event && id == SWITCH_EVENT_ALL) || (!source->any_event && source->selected[id])) {
				engine->buckets[id].rules[written[id]++] = &engine->rules[r];
			}
		}
	}
	if (engine->buckets[SWITCH_EVENT_ALL].count) {
		engine->subscriptions[0].event_id = SWITCH_EVENT_ALL;
		engine->subscription_count = 1;
	} else {
		for (id = 0; id < SWITCH_EVENT_ALL; id++) {
			if (engine->buckets[id].count) {
				engine->subscriptions[engine->subscription_count++].event_id = (switch_event_types_t) id;
			}
		}
	}
	*out = engine;
	return MOD_AMQP_FILTER_OK;
overflow:
	mod_amqp_filter_engine_destroy(&engine);
	return amqp_filter_error(error, MOD_AMQP_FILTER_LIMIT, error_rule, 0, error_condition, "Engine allocation overflow");
nomem:
	mod_amqp_filter_engine_destroy(&engine);
	return amqp_filter_error(error, MOD_AMQP_FILTER_NO_MEMORY, error_rule, 0, error_condition, "Cannot allocate compiled engine");
}

const mod_amqp_filter_subscription_t *mod_amqp_filter_subscriptions(
	const mod_amqp_filter_engine_t *engine, size_t *count)
{
	if (count) *count = engine ? engine->subscription_count : 0;
	return engine && engine->subscription_count ? engine->subscriptions : NULL;
}
