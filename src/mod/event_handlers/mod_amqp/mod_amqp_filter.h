/* Standalone whitelist preparation and matching. No producer integration. */
#ifndef MOD_AMQP_FILTER_H
#define MOD_AMQP_FILTER_H

#include <switch.h>

SWITCH_BEGIN_EXTERN_C

#define MOD_AMQP_FILTER_MAX_RULES 1024u
#define MOD_AMQP_FILTER_MAX_CONDITIONS 32u
#define MOD_AMQP_FILTER_MAX_VALUE_BYTES 4096u
#define MOD_AMQP_FILTER_MAX_FIELD_BYTES 255u
/* Per DTO / engine, including terminating NULs of copied fields and values. */
#define MOD_AMQP_FILTER_MAX_STRING_BYTES (4u * 1024u * 1024u)
#define MOD_AMQP_FILTER_BUCKETS ((size_t) SWITCH_EVENT_ALL + 1u)

typedef enum {
	MOD_AMQP_FILTER_OK = 0,
	MOD_AMQP_FILTER_INVALID,
	MOD_AMQP_FILTER_LIMIT,
	MOD_AMQP_FILTER_NO_MEMORY
} mod_amqp_filter_status_t;

typedef struct {
	mod_amqp_filter_status_t code;
	/* 1-based positions; zero means not applicable. No invented XML line. */
	size_t rule;
	size_t selector;
	size_t condition;
	char message[192];
} mod_amqp_filter_error_t;

typedef struct mod_amqp_filter_dto_s mod_amqp_filter_dto_t;
typedef struct mod_amqp_filter_engine_s mod_amqp_filter_engine_t;

typedef struct {
	switch_event_types_t event_id;
	/* Always SWITCH_EVENT_SUBCLASS_ANY (NULL) in v1. */
	const char *subclass;
} mod_amqp_filter_subscription_t;

/* Core event names must be initialized. XML stays caller-owned and unmodified.
 * Outputs must be empty slots, not handles to live objects. On error *out=NULL.
 * Each successful output owns independent heap memory; no active pool is used.
 * error may be NULL. Parsing validates the strict standalone XML contract.
 */
mod_amqp_filter_status_t mod_amqp_filter_parse(switch_xml_t xml,
	mod_amqp_filter_dto_t **out, mod_amqp_filter_error_t *error);
void mod_amqp_filter_dto_destroy(mod_amqp_filter_dto_t **dto);

/* Compilation revalidates the DTO and copies all required strings. The XML
 * and DTO may be destroyed immediately afterwards. No external resources.
 */
mod_amqp_filter_status_t mod_amqp_filter_compile(const mod_amqp_filter_dto_t *dto,
	mod_amqp_filter_engine_t **out, mod_amqp_filter_error_t *error);
void mod_amqp_filter_engine_destroy(mod_amqp_filter_engine_t **engine);

/* Borrowed immutable plan, valid until engine destruction. Empty/NULL engine
 * returns NULL and count=0. count may be NULL. No registration is performed.
 */
const mod_amqp_filter_subscription_t *mod_amqp_filter_subscriptions(
	const mod_amqp_filter_engine_t *engine, size_t *count);

/* Read-only, allocation-free; concurrent readers may share an engine. Caller
 * keeps the event stable and keeps the engine alive until all readers finish.
 * Concurrent destruction or mutation of either object is not supported.
 */
switch_bool_t mod_amqp_filter_match(const mod_amqp_filter_engine_t *engine,
	const switch_event_t *event);

SWITCH_END_EXTERN_C
#endif
