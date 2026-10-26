#ifndef MOD_AMQP_FILTER_INTERNAL_H
#define MOD_AMQP_FILTER_INTERNAL_H

#include "mod_amqp_filter.h"
#include <stdint.h>

typedef enum {
	AMQP_FILTER_HEADER,
	AMQP_FILTER_SUBCLASS
} amqp_filter_field_t;

typedef struct {
	amqp_filter_field_t kind;
	char *field;
	char *value;
} amqp_filter_condition_t;

typedef struct {
	unsigned char selected[MOD_AMQP_FILTER_BUCKETS];
	switch_bool_t any_event;
	size_t condition_count;
	amqp_filter_condition_t *conditions;
} amqp_filter_dto_rule_t;

struct mod_amqp_filter_dto_s {
	size_t rule_count;
	amqp_filter_dto_rule_t *rules;
};

typedef struct {
	size_t condition_count;
	amqp_filter_condition_t *conditions;
} amqp_filter_rule_t;

typedef struct {
	size_t count;
	const amqp_filter_rule_t **rules;
} amqp_filter_bucket_t;

struct mod_amqp_filter_engine_s {
	size_t rule_count;
	amqp_filter_rule_t *rules;
	amqp_filter_bucket_t buckets[MOD_AMQP_FILTER_BUCKETS];
	const amqp_filter_rule_t **index_entries;
	size_t subscription_count;
	mod_amqp_filter_subscription_t subscriptions[MOD_AMQP_FILTER_BUCKETS];
};

/* Small pure helpers shared by preparation and matching. ASCII case folding
 * avoids locale state; FreeSWITCH header names are compared as byte strings.
 */
static inline int amqp_filter_field_equal(const char *a, const char *b)
{
	unsigned char x, y;
	do {
		x = (unsigned char) *a++;
		y = (unsigned char) *b++;
		if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
		if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
		if (x != y) return 0;
	} while (x);
	return 1;
}

static inline int amqp_filter_add_size(size_t a, size_t b, size_t *out)
{
	if (a > SIZE_MAX - b) return 0;
	*out = a + b;
	return 1;
}

static inline int amqp_filter_mul_size(size_t a, size_t b, size_t *out)
{
	if (b && a > SIZE_MAX / b) return 0;
	*out = a * b;
	return 1;
}

static inline mod_amqp_filter_status_t amqp_filter_error(mod_amqp_filter_error_t *error,
	mod_amqp_filter_status_t code, size_t rule, size_t selector, size_t condition, const char *message)
{
	if (error) {
		error->code = code;
		error->rule = rule;
		error->selector = selector;
		error->condition = condition;
		switch_snprintf(error->message, sizeof(error->message), "%s", message);
	}
	return code;
}

/* Counts bytes including NUL against an independent object's string budget. */
static inline mod_amqp_filter_status_t amqp_filter_string_size(const char *s,
	size_t limit, size_t *total, size_t *bytes)
{
	size_t n = 0, sum;
	if (!s) return MOD_AMQP_FILTER_INVALID;
	while (n <= limit && s[n]) n++;
	if (n > limit || !amqp_filter_add_size(n, 1, bytes) ||
		!amqp_filter_add_size(*total, *bytes, &sum) || sum > MOD_AMQP_FILTER_MAX_STRING_BYTES) {
		return MOD_AMQP_FILTER_LIMIT;
	}
	*total = sum;
	return MOD_AMQP_FILTER_OK;
}

#endif
