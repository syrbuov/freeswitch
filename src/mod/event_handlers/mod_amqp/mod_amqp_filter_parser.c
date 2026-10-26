#include "mod_amqp_filter_internal.h"

/* Read explicit attributes only; XML DTD defaults must not supply required
 * mode/name/field/op/value attributes that are absent from the element. */
static const char *amqp_filter_attr(switch_xml_t xml, const char *name)
{
	size_t i;
	if (xml->attr) {
		for (i = 0; xml->attr[i]; i += 2) {
			if (!strcmp(xml->attr[i], name)) return xml->attr[i + 1];
		}
	}
	return NULL;
}

static int amqp_filter_blank(const char *text)
{
	if (!text) return 1;
	for (; *text; text++) {
		if (*text != ' ' && *text != '\t' && *text != '\r' && *text != '\n') return 0;
	}
	return 1;
}

static int amqp_filter_attributes(switch_xml_t xml, const char *a, const char *b, const char *c)
{
	size_t i, j;
	if (!xml->attr) return 1;
	for (i = 0; xml->attr[i]; i += 2) {
		if (!xml->attr[i + 1]) return 0;
		for (j = 0; j < i; j += 2) {
			if (!strcmp(xml->attr[i], xml->attr[j])) return 0;
		}
		if ((!a || strcmp(xml->attr[i], a)) && (!b || strcmp(xml->attr[i], b)) &&
			(!c || strcmp(xml->attr[i], c))) return 0;
	}
	return 1;
}

/* Exact EVENT_NAMES or SWITCH_EVENT_<EVENT_NAMES> spelling only. Never use
 * switch_name_event: it accepts case changes and arbitrary 13-byte prefixes.
 */
static int amqp_filter_event_id(const char *name, switch_event_types_t *id)
{
	int i;
	if (!name) return 0;
	if (!strncmp(name, "SWITCH_EVENT_", 13)) name += 13;
	for (i = 0; i <= SWITCH_EVENT_ALL; i++) {
		if (!strcmp(name, switch_event_name((switch_event_types_t) i))) {
			*id = (switch_event_types_t) i;
			return 1;
		}
	}
	return 0;
}

static mod_amqp_filter_status_t amqp_filter_validate_xml(switch_xml_t xml,
	size_t *rule_count, mod_amqp_filter_error_t *error)
{
	switch_xml_t rule, node;
	size_t total = 0, rn = 0;
	const char *mode;
	if (!xml || !xml->name || strcmp(xml->name, "filter")) {
		return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, 0, 0, 0, "Expected <filter> root");
	}
	if (*switch_xml_error(xml)) {
		return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, 0, 0, 0, "Malformed XML");
	}
	mode = amqp_filter_attr(xml, "mode");
	if (!mode || strcmp(mode, "rules") || !amqp_filter_attributes(xml, "mode", NULL, NULL) ||
		!amqp_filter_blank(xml->txt)) {
		return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, 0, 0, 0, "Expected mode=rules, no other attributes or text");
	}
	for (rule = xml->child; rule; rule = rule->ordered) {
		size_t cn = 0, sn = 0;
		if (++rn > MOD_AMQP_FILTER_MAX_RULES) {
			return amqp_filter_error(error, MOD_AMQP_FILTER_LIMIT, rn, 0, 0, "Too many rules");
		}
		if (strcmp(rule->name, "rule") || !amqp_filter_attributes(rule, NULL, NULL, NULL) ||
			!amqp_filter_blank(rule->txt)) {
			return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, rn, 0, 0, "Expected <rule> without attributes or text");
		}
		for (node = rule->child; node; node = node->ordered) {
			if (!strcmp(node->name, "event")) {
				switch_event_types_t id;
				sn++;
				if (!amqp_filter_attributes(node, "name", NULL, NULL) || node->child ||
					!amqp_filter_blank(node->txt) || !amqp_filter_event_id(amqp_filter_attr(node, "name"), &id)) {
					return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, rn, sn, 0, "Expected canonical event name and no other content");
				}
			} else if (!strcmp(node->name, "condition")) {
				const char *field = amqp_filter_attr(node, "field");
				const char *op = amqp_filter_attr(node, "op");
				const char *value = amqp_filter_attr(node, "value");
				size_t bytes;
				mod_amqp_filter_status_t status;
				if (++cn > MOD_AMQP_FILTER_MAX_CONDITIONS) {
					return amqp_filter_error(error, MOD_AMQP_FILTER_LIMIT, rn, 0, cn, "Too many conditions");
				}
				if (!amqp_filter_attributes(node, "field", "op", "value") || node->child ||
					!amqp_filter_blank(node->txt) || !field || !*field || !op || strcmp(op, "eq") || !value) {
					return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, rn, 0, cn, "Expected field, op=eq and value, without other content");
				}
				if (amqp_filter_field_equal(field, "Event-Name") || amqp_filter_field_equal(field, "_body")) {
					return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, rn, 0, cn, "Event-Name requires <event>; _body is unsupported");
				}
				status = amqp_filter_string_size(field, MOD_AMQP_FILTER_MAX_FIELD_BYTES, &total, &bytes);
				if (status == MOD_AMQP_FILTER_OK) {
					status = amqp_filter_string_size(value, MOD_AMQP_FILTER_MAX_VALUE_BYTES, &total, &bytes);
				}
				if (status != MOD_AMQP_FILTER_OK) {
					return amqp_filter_error(error, status, rn, 0, cn, "Field, value or total copied strings exceed limit");
				}
			} else {
				return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, rn, 0, 0, "Unknown rule element");
			}
		}
		if (!cn && !sn) {
			return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, rn, 0, 0, "Empty rule; use explicit <event name=ALL> to allow all");
		}
	}
	*rule_count = rn;
	return MOD_AMQP_FILTER_OK;
}

void mod_amqp_filter_dto_destroy(mod_amqp_filter_dto_t **handle)
{
	mod_amqp_filter_dto_t *dto;
	size_t r, c;
	if (!handle || !(dto = *handle)) return;
	if (dto->rules) {
		for (r = 0; r < dto->rule_count; r++) {
			amqp_filter_dto_rule_t *rule = &dto->rules[r];
			if (rule->conditions) {
				for (c = 0; c < rule->condition_count; c++) {
					free(rule->conditions[c].field);
					free(rule->conditions[c].value);
				}
				free(rule->conditions);
			}
		}
		free(dto->rules);
	}
	free(dto);
	*handle = NULL;
}

mod_amqp_filter_status_t mod_amqp_filter_parse(switch_xml_t xml,
	mod_amqp_filter_dto_t **out, mod_amqp_filter_error_t *error)
{
	mod_amqp_filter_dto_t *dto = NULL;
	mod_amqp_filter_status_t status;
	switch_xml_t rule, node;
	size_t count = 0, r = 0, c = 0, sn = 0, bytes, error_rule = 0, error_condition = 0;
	amqp_filter_error(error, MOD_AMQP_FILTER_OK, 0, 0, 0, "");
	if (!out) return amqp_filter_error(error, MOD_AMQP_FILTER_INVALID, 0, 0, 0, "Missing DTO output");
	*out = NULL;
	status = amqp_filter_validate_xml(xml, &count, error);
	if (status != MOD_AMQP_FILTER_OK) return status;
	if (!amqp_filter_mul_size(count, sizeof(*dto->rules), &bytes)) {
		return amqp_filter_error(error, MOD_AMQP_FILTER_LIMIT, 0, 0, 0, "Rule allocation overflow");
	}
	if (!(dto = calloc(1, sizeof(*dto)))) goto nomem;
	dto->rule_count = count;
	if (count && !(dto->rules = calloc(1, bytes))) goto nomem;
	for (rule = xml->child; rule; rule = rule->ordered, r++) {
		amqp_filter_dto_rule_t *dest = &dto->rules[r];
		error_rule = r + 1;
		c = sn = 0;
		for (node = rule->child; node; node = node->ordered) {
			if (!strcmp(node->name, "condition")) dest->condition_count++;
		}
		if (!amqp_filter_mul_size(dest->condition_count, sizeof(*dest->conditions), &bytes)) goto overflow;
		if (bytes && !(dest->conditions = calloc(1, bytes))) goto nomem;
		for (node = rule->child; node; node = node->ordered) {
			if (!strcmp(node->name, "event")) {
				switch_event_types_t id = SWITCH_EVENT_ALL;
				sn++;
				amqp_filter_event_id(amqp_filter_attr(node, "name"), &id);
				if (id == SWITCH_EVENT_ALL) dest->any_event = SWITCH_TRUE;
				else dest->selected[id] = 1;
			} else {
				amqp_filter_condition_t *condition = &dest->conditions[c++];
				const char *field = amqp_filter_attr(node, "field");
				const char *value = amqp_filter_attr(node, "value");
				error_condition = c;
				condition->kind = amqp_filter_field_equal(field, "Event-Subclass") ? AMQP_FILTER_SUBCLASS : AMQP_FILTER_HEADER;
				bytes = strlen(field) + 1; /* Bounds and sum validated before allocation. */
				if (!(condition->field = malloc(bytes))) goto nomem;
				memcpy(condition->field, field, bytes);
				bytes = strlen(value) + 1;
				if (!(condition->value = malloc(bytes))) goto nomem;
				memcpy(condition->value, value, bytes);
				error_condition = 0;
			}
		}
		if (!sn) dest->any_event = SWITCH_TRUE;
		if (dest->any_event) memset(dest->selected, 0, sizeof(dest->selected));
	}
	*out = dto;
	return MOD_AMQP_FILTER_OK;
overflow:
	mod_amqp_filter_dto_destroy(&dto);
	return amqp_filter_error(error, MOD_AMQP_FILTER_LIMIT, error_rule, 0, error_condition, "Condition allocation overflow");
nomem:
	mod_amqp_filter_dto_destroy(&dto);
	return amqp_filter_error(error, MOD_AMQP_FILTER_NO_MEMORY, error_rule, 0, error_condition, "Cannot allocate parser DTO");
}
