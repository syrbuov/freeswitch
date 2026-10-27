/* Production engine, with test-local allocation accounting and fault injection.
 * Real FreeSWITCH XML, events and headers; no RabbitMQ or producer required.
 */
#include "mod_amqp_filter.h"
#include <test/switch_test.h>

static size_t allocation_calls, fail_allocation;
static long live_allocations;
static int matching, allocations_in_match, forbidden_external_calls;

static int allocation_fails(void)
{
	size_t call = __sync_add_and_fetch(&allocation_calls, 1);
	if (matching) __sync_add_and_fetch(&allocations_in_match, 1);
	return fail_allocation && call == fail_allocation;
}

static void *filter_test_malloc(size_t size)
{
	void *p;
	if (allocation_fails()) return NULL;
	p = malloc(size);
	if (p) __sync_add_and_fetch(&live_allocations, 1);
	return p;
}

static void *filter_test_calloc(size_t count, size_t size)
{
	void *p;
	if (allocation_fails()) return NULL;
	p = calloc(count, size);
	if (p) __sync_add_and_fetch(&live_allocations, 1);
	return p;
}

static void filter_test_free(void *p)
{
	if (p) __sync_sub_and_fetch(&live_allocations, 1);
	free(p);
}

#define malloc filter_test_malloc
#define calloc filter_test_calloc
#define free filter_test_free
/* Any direct use by preparation/matcher fails the tests without side effects.
 * Macros apply only to the included engine, not Core or the fixture below.
 */
#define switch_event_bind_removable(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_event_bind(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_event_unbind(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_event_unbind_callback(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_thread_create(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_queue_create(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_queue_trypush(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_queue_push(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_event_serialize_json(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_core_hash_insert_destructor(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#define switch_core_hash_delete(...) (++forbidden_external_calls, SWITCH_STATUS_GENERR)
#include "../mod_amqp_filter_parser.c"
#include "../mod_amqp_filter_compiler.c"
#include "../mod_amqp_filter_matcher.c"
#undef malloc
#undef calloc
#undef free
#undef switch_event_bind_removable
#undef switch_event_bind
#undef switch_event_unbind
#undef switch_event_unbind_callback
#undef switch_thread_create
#undef switch_queue_create
#undef switch_queue_trypush
#undef switch_queue_push
#undef switch_event_serialize_json
#undef switch_core_hash_insert_destructor
#undef switch_core_hash_delete

static switch_xml_t test_xml(const char *text)
{
	/* The dup=true API copies before parsing, despite its mutable signature. */
	switch_xml_t xml = switch_xml_parse_str_dynamic((char *) text, SWITCH_TRUE);
	switch_assert(xml && !*switch_xml_error(xml));
	return xml;
}

static mod_amqp_filter_engine_t *test_engine(const char *text)
{
	switch_xml_t xml = test_xml(text);
	mod_amqp_filter_dto_t *dto = NULL;
	mod_amqp_filter_engine_t *engine = NULL;
	mod_amqp_filter_error_t error;
	switch_assert(mod_amqp_filter_parse(xml, &dto, &error) == MOD_AMQP_FILTER_OK);
	switch_xml_free(xml);
	switch_assert(mod_amqp_filter_compile(dto, &engine, &error) == MOD_AMQP_FILTER_OK);
	mod_amqp_filter_dto_destroy(&dto);
	return engine;
}

static mod_amqp_filter_status_t test_parse_status(const char *text, mod_amqp_filter_error_t *error)
{
	switch_xml_t xml = switch_xml_parse_str_dynamic((char *) text, SWITCH_TRUE);
	mod_amqp_filter_dto_t *dto = NULL;
	mod_amqp_filter_status_t status = mod_amqp_filter_parse(xml, &dto, error);
	if (status != MOD_AMQP_FILTER_OK) switch_assert(dto == NULL);
	mod_amqp_filter_dto_destroy(&dto);
	if (xml) switch_xml_free(xml);
	return status;
}

static switch_event_t *test_event(switch_event_types_t id)
{
	switch_event_t *event = NULL;
	switch_assert(switch_event_create(&event, id) == SWITCH_STATUS_SUCCESS);
	/* Core's CLONE constructor intentionally leaves event_id zero. Tests of
	 * the whole enum explicitly set the requested internal ID afterwards. */
	event->event_id = id;
	return event;
}

/* Bounded test input generator. first_extra changes only the first value. */
static char *test_large_xml(size_t rules, size_t conditions, size_t field_size, size_t value_size, size_t first_extra)
{
	size_t r, c, capacity = 100 + rules * (80 + conditions * (80 + field_size + value_size + first_extra));
	char *text = malloc(capacity), *p = text;
	switch_assert(text);
	p += sprintf(p, "<filter mode=\"rules\">");
	for (r = 0; r < rules; r++) {
		p += sprintf(p, "<rule><event name=\"CUSTOM\"/>");
		for (c = 0; c < conditions; c++) {
			size_t n = value_size + ((!r && !c) ? first_extra : 0);
			p += sprintf(p, "<condition field=\"");
			memset(p, 'x', field_size); p += field_size;
			p += sprintf(p, "\" op=\"eq\" value=\"");
			memset(p, 'v', n); p += n;
			p += sprintf(p, "\"/>");
		}
		p += sprintf(p, "</rule>");
	}
	p += sprintf(p, "</filter>");
	switch_assert((size_t) (p - text) < capacity);
	return text;
}

typedef struct {
	const mod_amqp_filter_engine_t *engine;
	switch_event_t *event;
	switch_bool_t expected;
	int failed;
} filter_reader_t;

static void *SWITCH_THREAD_FUNC filter_reader(switch_thread_t *thread, void *data)
{
	filter_reader_t *reader = data;
	int i;
	for (i = 0; i < 20000; i++) {
		if (mod_amqp_filter_match(reader->engine, reader->event) != reader->expected) reader->failed = 1;
	}
	switch_thread_exit(thread, SWITCH_STATUS_SUCCESS);
	return NULL;
}

FST_BEGIN()
{
	/* Matching needs names and real event/header APIs, not event delivery.
	 * Sanitizer runs may select minimal Core to isolate unrelated subsystems.
	 * All engine tests, including real reader threads, still run unchanged. */
	int minimal = getenv("MOD_AMQP_FILTER_TEST_MINIMAL") != NULL;
	/* Prevent the empty-module-list fallback from loading installed DSOs. */
	SWITCH_GLOBAL_dirs.mod_dir = strdup(SWITCH_TEST_BASE_DIR_FOR_CONF "/conf");
	if (fst_init_core_and_modload("conf", NULL, minimal, SCF_LOG_DISABLE) != SWITCH_STATUS_SUCCESS) exit(1);
	{
	FST_SUITE_BEGIN(mod_amqp_filter_engine)
	{
		FST_SETUP_BEGIN()
		{
			allocation_calls = fail_allocation = 0;
			matching = allocations_in_match = forbidden_external_calls = 0;
			switch_assert(live_allocations == 0);
		}
		FST_SETUP_END()
		FST_TEARDOWN_BEGIN()
		{
			switch_assert(live_allocations == 0 && allocations_in_match == 0 && forbidden_external_calls == 0);
		}
		FST_TEARDOWN_END()

		FST_TEST_BEGIN(empty_whitelist_and_null_arguments)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"/>");
			mod_amqp_filter_dto_t *dto = NULL;
			mod_amqp_filter_error_t error;
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			size_t count = 99;
			fst_check(!mod_amqp_filter_match(engine, event));
			fst_check(!mod_amqp_filter_match(NULL, event) && !mod_amqp_filter_match(engine, NULL));
			fst_check(mod_amqp_filter_subscriptions(engine, &count) == NULL && count == 0);
			fst_check(mod_amqp_filter_subscriptions(NULL, &count) == NULL && count == 0);
			fst_check(mod_amqp_filter_subscriptions(NULL, NULL) == NULL);
			fst_check(mod_amqp_filter_parse(NULL, &dto, &error) == MOD_AMQP_FILTER_INVALID && dto == NULL);
			fst_check(mod_amqp_filter_parse(NULL, NULL, NULL) == MOD_AMQP_FILTER_INVALID);
			fst_check(mod_amqp_filter_compile(NULL, NULL, NULL) == MOD_AMQP_FILTER_INVALID);
			mod_amqp_filter_engine_destroy(&engine);
			fst_check(mod_amqp_filter_compile(NULL, &engine, &error) == MOD_AMQP_FILTER_INVALID && engine == NULL);
			mod_amqp_filter_engine_destroy(NULL);
			mod_amqp_filter_engine_destroy(&engine);
			mod_amqp_filter_dto_destroy(NULL);
			mod_amqp_filter_dto_destroy(&dto);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(strict_schema_and_diagnostics)
		{
			const char *bad[] = {
				"<filter/>", "<filter mode=\"legacy\"/>", "<filter mode=\"RULES\"/>",
				"<filters mode=\"rules\"/>", "<filter mode=\"rules\" extra=\"x\"/>",
				"<filter mode=\"rules\"><deny/></filter>", "<filter mode=\"rules\">text</filter>",
				"<filter mode=\"rules\"><rule/></filter>", "<filter mode=\"rules\"><rule id=\"1\"/></filter>",
				"<filter mode=\"rules\"><rule><event name=\"UNKNOWN\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><event/></rule></filter>",
				"<filter mode=\"rules\"><rule><event name=\"CUSTOM\" extra=\"x\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><event name=\"CUSTOM\"><nested/></event></rule></filter>",
				"<filter mode=\"rules\"><rule><event name=\"CUSTOM\">text</event></rule></filter>",
				"<filter mode=\"rules\"><rule><unknown/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"x\" op=\"ne\" value=\"a\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"\" op=\"eq\" value=\"a\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"x\" value=\"a\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition op=\"eq\" value=\"a\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"a\" extra=\"x\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"a\"><event/></condition></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"a\">text</condition></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"eVeNt-NaMe\" op=\"eq\" value=\"CUSTOM\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"_BoDy\" op=\"eq\" value=\"a\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/>",
				"<filter mode=\"rules\" mode=\"legacy\"/>",
				"<filter mode=\"rules\"/><other/>",
				"<!DOCTYPE filter [<!ATTLIST filter mode CDATA \"rules\">]><filter/>", NULL
			};
			mod_amqp_filter_error_t error;
			int i;
			for (i = 0; bad[i]; i++) {
				fst_check(test_parse_status(bad[i], &error) == MOD_AMQP_FILTER_INVALID);
				fst_check(error.code == MOD_AMQP_FILTER_INVALID && *error.message);
			}
			fst_check(test_parse_status("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/></rule><rule><event name=\"bad\"/></rule></filter>", &error) == MOD_AMQP_FILTER_INVALID);
			fst_check(error.rule == 2 && error.selector == 1 && error.condition == 0);
			fst_check(test_parse_status("<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"a\"/><condition field=\"x\" op=\"bad\" value=\"b\"/></rule></filter>", &error) == MOD_AMQP_FILTER_INVALID);
			fst_check(error.rule == 1 && error.condition == 2 && error.selector == 0);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(exact_event_names_both_spellings)
		{
			int id, prefixed;
			const char *bad[] = { "custom", "SWITCH_EVENT_custom", "switch_event_CUSTOM", "CHAN", "CUSTOM ", " CUSTOM", "XXXXXXXXXXXXX_CUSTOM", "1234567890123CUSTOM", "SWITCH_EVENT_", "SWITCH_EVENT_SWITCH_EVENT_CUSTOM", NULL };
			mod_amqp_filter_error_t error;
			for (id = 0; id <= SWITCH_EVENT_ALL; id++) {
				for (prefixed = 0; prefixed < 2; prefixed++) {
					char *text = switch_mprintf("<filter mode=\"rules\"><rule><event name=\"%s%s\"/></rule></filter>", prefixed ? "SWITCH_EVENT_" : "", switch_event_name((switch_event_types_t) id));
					mod_amqp_filter_engine_t *engine = test_engine(text);
					switch_event_t *event = test_event((switch_event_types_t) id);
					fst_check(mod_amqp_filter_match(engine, event));
					mod_amqp_filter_engine_destroy(&engine);
					switch_event_destroy(&event);
					free(text);
				}
			}
			for (id = 0; bad[id]; id++) {
				char *text = switch_mprintf("<filter mode=\"rules\"><rule><event name=\"%s\"/></rule></filter>", bad[id]);
				fst_check(test_parse_status(text, &error) == MOD_AMQP_FILTER_INVALID);
				free(text);
			}
		}
		FST_TEST_END()

		FST_TEST_BEGIN(or_rules_and_conditions_and_boolean_result)
		{
			mod_amqp_filter_engine_t *engine = test_engine(
				"<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><condition field=\"x\" op=\"eq\" value=\"a\"/><condition field=\"y\" op=\"eq\" value=\"b\"/></rule>"
				"<rule><event name=\"DTMF\"/><event name=\"HEARTBEAT\"/><condition field=\"z\" op=\"eq\" value=\"c\"/></rule>"
				"<rule><event name=\"CUSTOM\"/><condition field=\"x\" op=\"eq\" value=\"a\"/></rule></filter>");
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "y", "b");
			fst_check(!mod_amqp_filter_match(engine, event));
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x", "a");
			fst_check(mod_amqp_filter_match(engine, event) == SWITCH_TRUE);
			event->event_id = SWITCH_EVENT_DTMF;
			fst_check(!mod_amqp_filter_match(engine, event));
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "z", "c");
			fst_check(mod_amqp_filter_match(engine, event));
			event->event_id = SWITCH_EVENT_HEARTBEAT;
			fst_check(mod_amqp_filter_match(engine, event));
			event->event_id = SWITCH_EVENT_CHANNEL_CREATE;
			fst_check(!mod_amqp_filter_match(engine, event));
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(index_normalization_and_unique_subscription_plan)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><event name=\"SWITCH_EVENT_CUSTOM\"/><event name=\"DTMF\"/></rule><rule><event name=\"DTMF\"/></rule></filter>");
			const mod_amqp_filter_subscription_t *plan;
			size_t count;
			plan = mod_amqp_filter_subscriptions(engine, &count);
			fst_check(count == 2 && plan[0].event_id == SWITCH_EVENT_CUSTOM && plan[1].event_id == SWITCH_EVENT_DTMF);
			fst_check(plan[0].subclass == NULL && plan[1].subclass == NULL);
			fst_check(engine->buckets[SWITCH_EVENT_CUSTOM].count == 1 && engine->buckets[SWITCH_EVENT_DTMF].count == 2);
			fst_check(engine->buckets[SWITCH_EVENT_ALL].count == 0);
			mod_amqp_filter_engine_destroy(&engine);
			engine = test_engine("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><event name=\"ALL\"/><event name=\"SWITCH_EVENT_ALL\"/></rule><rule><event name=\"DTMF\"/></rule></filter>");
			plan = mod_amqp_filter_subscriptions(engine, &count);
			fst_check(count == 1 && plan[0].event_id == SWITCH_EVENT_ALL && plan[0].subclass == NULL);
			fst_check(engine->buckets[SWITCH_EVENT_ALL].count == 1 && engine->buckets[SWITCH_EVENT_CUSTOM].count == 0);
			fst_check(engine->buckets[SWITCH_EVENT_DTMF].count == 1);
			mod_amqp_filter_engine_destroy(&engine);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(specific_and_general_buckets_and_id_boundaries)
		{
			char *text = switch_mprintf("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/></rule><rule><event name=\"%s\"/></rule><rule><condition field=\"x\" op=\"eq\" value=\"a\"/></rule></filter>", switch_event_name((switch_event_types_t) (SWITCH_EVENT_ALL - 1)));
			mod_amqp_filter_engine_t *engine = test_engine(text);
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			fst_check(SWITCH_EVENT_CUSTOM == 0 && mod_amqp_filter_match(engine, event));
			event->event_id = (switch_event_types_t) (SWITCH_EVENT_ALL - 1);
			fst_check(mod_amqp_filter_match(engine, event));
			event->event_id = SWITCH_EVENT_DTMF;
			fst_check(!mod_amqp_filter_match(engine, event));
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x", "a");
			fst_check(mod_amqp_filter_match(engine, event));
			event->event_id = SWITCH_EVENT_ALL;
			fst_check(mod_amqp_filter_match(engine, event));
			event->event_id = (switch_event_types_t) -1;
			fst_check(!mod_amqp_filter_match(engine, event));
			event->event_id = (switch_event_types_t) (SWITCH_EVENT_ALL + 1);
			fst_check(!mod_amqp_filter_match(engine, event));
			event->event_id = (switch_event_types_t) INT_MAX;
			fst_check(!mod_amqp_filter_match(engine, event));
			free(text);
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(canonical_fields_override_same_named_headers)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><condition field=\"eVeNt-SuBcLaSs\" op=\"eq\" value=\"real::subclass\"/></rule></filter>");
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			switch_event_set_subclass_name(event, "real::subclass");
			switch_event_del_header(event, "Event-Subclass");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Event-Subclass", "fake::subclass");
			switch_event_del_header(event, "Event-Name");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Event-Name", "DTMF");
			fst_check(mod_amqp_filter_match(engine, event));
			event->event_id = SWITCH_EVENT_DTMF;
			fst_check(!mod_amqp_filter_match(engine, event));
			event->event_id = SWITCH_EVENT_CUSTOM;
			free(event->subclass_name); event->subclass_name = NULL;
			switch_event_del_header(event, "Event-Subclass");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Event-Subclass", "real::subclass");
			fst_check(!mod_amqp_filter_match(engine, event));
			switch_event_set_subclass_name(event, "Real::subclass");
			fst_check(!mod_amqp_filter_match(engine, event));
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(header_case_missing_and_empty_values)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><condition field=\"VaRiAbLe_TeNaNt\" op=\"eq\" value=\"acme\"/></rule></filter>");
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			fst_check(!mod_amqp_filter_match(engine, event));
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "variable_tenant", "Acme");
			fst_check(!mod_amqp_filter_match(engine, event));
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "VARIABLE_TENANT", "acme");
			fst_check(mod_amqp_filter_match(engine, event));
			mod_amqp_filter_engine_destroy(&engine);
			engine = test_engine("<filter mode=\"rules\"><rule><condition field=\"empty\" op=\"eq\" value=\"\"/></rule></filter>");
			fst_check(!mod_amqp_filter_match(engine, event));
			/* Core deletes empty scalar additions. PUSH an empty array element. */
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "empty", "seed");
			switch_event_add_header_string(event, SWITCH_STACK_PUSH, "empty", "");
			fst_check(mod_amqp_filter_match(engine, event));
			mod_amqp_filter_engine_destroy(&engine);
			engine = test_engine("<filter mode=\"rules\"><rule><condition field=\"Event-Subclass\" op=\"eq\" value=\"\"/></rule></filter>");
			fst_check(!mod_amqp_filter_match(engine, event));
			switch_event_set_subclass_name(event, "");
			fst_check(mod_amqp_filter_match(engine, event));
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(scalar_push_unshift_and_indexed_arrays)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"first\"/><condition field=\"x\" op=\"eq\" value=\"last\"/></rule></filter>");
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x", "middle");
			switch_event_add_header_string(event, SWITCH_STACK_PUSH, "x", "last");
			switch_event_add_header_string(event, SWITCH_STACK_UNSHIFT, "x", "first");
			fst_check(mod_amqp_filter_match(engine, event));
			fst_check(switch_event_get_header_ptr(event, "x")->idx == 3);
			switch_event_del_header(event, "x");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x[2]", "last");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x[0]", "first");
			fst_check(mod_amqp_filter_match(engine, event));
			mod_amqp_filter_engine_destroy(&engine);
			engine = test_engine("<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"\"/></rule></filter>");
			fst_check(mod_amqp_filter_match(engine, event)); /* Indexed hole is a real empty string. */
			mod_amqp_filter_engine_destroy(&engine);
			{
				/* Core may leave value stale after updating an existing array
				 * index. Reject the actual cached rendering, whatever its text. */
				char *text = switch_mprintf("<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"%s\"/></rule></filter>", switch_event_get_header(event, "x"));
				fst_check(!strncmp(switch_event_get_header(event, "x"), "ARRAY::", 7));
				engine = test_engine(text);
				free(text);
				fst_check(!mod_amqp_filter_match(engine, event));
			}
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(repeated_nodes_and_independent_any_conditions)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"one\"/><condition field=\"X\" op=\"eq\" value=\"two\"/><condition field=\"x\" op=\"eq\" value=\"three\"/></rule></filter>");
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x", "one");
			switch_event_add_header_string(event, SWITCH_STACK_PUSH, "x", "two");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "X", "three");
			fst_check(switch_event_get_header_ptr(event, "x")->next != NULL);
			fst_check(mod_amqp_filter_match(engine, event));
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(xml_and_dto_lifetimes_and_event_immutability)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><condition field=\"x\" op=\"eq\" value=\"a&amp;b\"/></rule></filter>");
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			switch_event_t original;
			char *before = NULL, *after = NULL;
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x", "a&b");
			switch_event_add_header_string(event, SWITCH_STACK_PUSH, "x", "other");
			switch_event_set_body(event, "body");
			switch_event_set_subclass_name(event, "immutable::subclass");
			original = *event;
			switch_event_serialize_json(event, &before);
			matching = 1;
			fst_check(mod_amqp_filter_match(engine, event));
			matching = 0;
			switch_event_serialize_json(event, &after);
			fst_check(!memcmp(&original, event, sizeof(original)) && !strcmp(before, after));
			free(before); free(after);
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(matcher_has_no_allocations_and_does_not_mutate_engine)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"absent\"/></rule><rule><event name=\"CUSTOM\"/><condition field=\"x\" op=\"eq\" value=\"b\"/></rule></filter>");
			mod_amqp_filter_engine_t original = *engine;
			switch_event_t *event = test_event(SWITCH_EVENT_CUSTOM);
			size_t calls = allocation_calls;
			int i;
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x", "a");
			switch_event_add_header_string(event, SWITCH_STACK_PUSH, "x", "b");
			matching = 1;
			for (i = 0; i < 1000; i++) fst_check(mod_amqp_filter_match(engine, event));
			matching = 0;
			fst_check(calls == allocation_calls && allocations_in_match == 0);
			fst_check(!memcmp(&original, engine, sizeof(original)));
			mod_amqp_filter_engine_destroy(&engine);
			switch_event_destroy(&event);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(parallel_readers_share_precompiled_engine)
		{
			mod_amqp_filter_engine_t *engine = test_engine("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><condition field=\"tenant\" op=\"eq\" value=\"acme\"/></rule><rule><condition field=\"other\" op=\"eq\" value=\"yes\"/></rule></filter>");
			filter_reader_t readers[8];
			switch_thread_t *threads[8];
			switch_memory_pool_t *pool = NULL;
			switch_status_t status;
			int i;
			switch_core_new_memory_pool(&pool);
			for (i = 0; i < 8; i++) {
				readers[i].engine = engine;
				readers[i].event = test_event(SWITCH_EVENT_CUSTOM);
				readers[i].expected = i % 2 ? SWITCH_TRUE : SWITCH_FALSE;
				readers[i].failed = 0;
				switch_event_add_header_string(readers[i].event, SWITCH_STACK_BOTTOM, "tenant", i % 2 ? "acme" : "other");
			}
			matching = 1;
			for (i = 0; i < 8; i++) switch_assert(switch_thread_create(&threads[i], NULL, filter_reader, &readers[i], pool) == SWITCH_STATUS_SUCCESS);
			for (i = 0; i < 8; i++) switch_assert(switch_thread_join(&status, threads[i]) == SWITCH_STATUS_SUCCESS);
			matching = 0;
			for (i = 0; i < 8; i++) {
				fst_check(!readers[i].failed);
				switch_event_destroy(&readers[i].event);
			}
			switch_core_destroy_memory_pool(&pool);
			mod_amqp_filter_engine_destroy(&engine);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(rule_condition_and_string_length_boundaries)
		{
			const size_t values[][4] = {
				{ MOD_AMQP_FILTER_MAX_RULES, 0, 1, 1 },
				{ 1, MOD_AMQP_FILTER_MAX_CONDITIONS, 1, 1 },
				{ 1, 1, MOD_AMQP_FILTER_MAX_FIELD_BYTES, 1 },
				{ 1, 1, 1, MOD_AMQP_FILTER_MAX_VALUE_BYTES }
			};
			mod_amqp_filter_error_t error;
			size_t i;
			for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
				char *text = test_large_xml(values[i][0], values[i][1], values[i][2], values[i][3], 0);
				mod_amqp_filter_engine_t *engine = test_engine(text);
				mod_amqp_filter_engine_destroy(&engine);
				free(text);
				text = test_large_xml(values[i][0] + (i == 0), values[i][1] + (i == 1), values[i][2] + (i == 2), values[i][3] + (i == 3), 0);
				fst_check(test_parse_status(text, &error) == MOD_AMQP_FILTER_LIMIT);
				free(text);
			}
		}
		FST_TEST_END()

		FST_TEST_BEGIN(total_copied_string_budget_boundary)
		{
			/* 32*32*(field 'x'+NUL + 4093 value bytes+NUL) == 4 MiB. */
			char *text = test_large_xml(32, 32, 1, 4093, 0);
			mod_amqp_filter_engine_t *engine = test_engine(text);
			mod_amqp_filter_error_t error;
			fst_check(MOD_AMQP_FILTER_MAX_STRING_BYTES == 32u * 32u * 4096u);
			mod_amqp_filter_engine_destroy(&engine);
			free(text);
			text = test_large_xml(32, 32, 1, 4093, 1);
			fst_check(test_parse_status(text, &error) == MOD_AMQP_FILTER_LIMIT);
			fst_check(error.rule == 32 && error.condition == 32);
			free(text);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(compiler_revalidation_and_size_overflow)
		{
			switch_xml_t xml = test_xml("<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"a\"/></rule></filter>");
			mod_amqp_filter_dto_t *dto = NULL;
			mod_amqp_filter_engine_t *engine = NULL;
			mod_amqp_filter_error_t error;
			size_t saved, result;
			fst_check(mod_amqp_filter_parse(xml, &dto, &error) == MOD_AMQP_FILTER_OK);
			switch_xml_free(xml);
			saved = dto->rule_count; dto->rule_count = MOD_AMQP_FILTER_MAX_RULES + 1;
			fst_check(mod_amqp_filter_compile(dto, &engine, &error) == MOD_AMQP_FILTER_LIMIT && engine == NULL);
			dto->rule_count = saved;
			saved = dto->rules[0].condition_count; dto->rules[0].condition_count = MOD_AMQP_FILTER_MAX_CONDITIONS + 1;
			fst_check(mod_amqp_filter_compile(dto, &engine, &error) == MOD_AMQP_FILTER_LIMIT && engine == NULL);
			dto->rules[0].condition_count = saved;
			filter_test_free(dto->rules[0].conditions[0].value);
			dto->rules[0].conditions[0].value = filter_test_malloc(MOD_AMQP_FILTER_MAX_VALUE_BYTES + 2);
			memset(dto->rules[0].conditions[0].value, 'a', MOD_AMQP_FILTER_MAX_VALUE_BYTES + 1);
			dto->rules[0].conditions[0].value[MOD_AMQP_FILTER_MAX_VALUE_BYTES + 1] = '\0';
			fst_check(mod_amqp_filter_compile(dto, &engine, &error) == MOD_AMQP_FILTER_LIMIT && engine == NULL);
			fst_check(error.rule == 1 && error.condition == 1);
			fst_check(!amqp_filter_add_size(SIZE_MAX, 1, &result));
			fst_check(!amqp_filter_mul_size(SIZE_MAX, 2, &result));
			fst_check(amqp_filter_add_size(SIZE_MAX - 1, 1, &result) && result == SIZE_MAX);
			fst_check(amqp_filter_mul_size(0, SIZE_MAX, &result) && result == 0);
			mod_amqp_filter_dto_destroy(&dto);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(parser_allocation_failures_leave_no_partial_dto)
		{
			switch_xml_t xml = test_xml("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><condition field=\"x\" op=\"eq\" value=\"a\"/></rule><rule><condition field=\"y\" op=\"eq\" value=\"b\"/></rule></filter>");
			mod_amqp_filter_dto_t *dto = NULL;
			mod_amqp_filter_error_t error;
			size_t n;
			int completed = 0;
			for (n = 1; n < 100; n++) {
				mod_amqp_filter_status_t status;
				allocation_calls = 0; fail_allocation = n;
				status = mod_amqp_filter_parse(xml, &dto, &error);
				fail_allocation = 0;
				if (status == MOD_AMQP_FILTER_OK) {
					mod_amqp_filter_dto_destroy(&dto); completed = 1; break;
				}
				fst_check(status == MOD_AMQP_FILTER_NO_MEMORY && dto == NULL && live_allocations == 0);
			}
			fst_check(completed && n > 5);
			switch_xml_free(xml);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(compiler_allocation_failures_leave_no_partial_engine)
		{
			switch_xml_t xml = test_xml("<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><condition field=\"x\" op=\"eq\" value=\"a\"/></rule><rule><condition field=\"y\" op=\"eq\" value=\"b\"/></rule></filter>");
			mod_amqp_filter_dto_t *dto = NULL;
			mod_amqp_filter_engine_t *engine = NULL;
			mod_amqp_filter_error_t error;
			long baseline_live;
			size_t n;
			int completed = 0;
			fst_check(mod_amqp_filter_parse(xml, &dto, &error) == MOD_AMQP_FILTER_OK);
			switch_xml_free(xml);
			baseline_live = live_allocations;
			for (n = 1; n < 100; n++) {
				mod_amqp_filter_status_t status;
				allocation_calls = 0; fail_allocation = n;
				status = mod_amqp_filter_compile(dto, &engine, &error);
				fail_allocation = 0;
				if (status == MOD_AMQP_FILTER_OK) {
					mod_amqp_filter_engine_destroy(&engine); completed = 1; break;
				}
				fst_check(status == MOD_AMQP_FILTER_NO_MEMORY && engine == NULL && live_allocations == baseline_live);
			}
			fst_check(completed && n > 5 && live_allocations == baseline_live);
			mod_amqp_filter_dto_destroy(&dto);
		}
		FST_TEST_END()

		FST_TEST_BEGIN(preparation_has_no_management_side_effects_and_plan_covers_matches)
		{
			const char *filters[] = {
				"<filter mode=\"rules\"/>",
				"<filter mode=\"rules\"><rule><event name=\"CUSTOM\"/><event name=\"HEARTBEAT\"/></rule></filter>",
				"<filter mode=\"rules\"><rule><condition field=\"x\" op=\"eq\" value=\"a\"/></rule><rule><event name=\"DTMF\"/></rule></filter>", NULL
			};
			int i, id;
			for (i = 0; filters[i]; i++) {
				mod_amqp_filter_engine_t *engine = test_engine(filters[i]);
				const mod_amqp_filter_subscription_t *plan;
				size_t count, p;
				plan = mod_amqp_filter_subscriptions(engine, &count);
				for (id = 0; id <= SWITCH_EVENT_ALL; id++) {
					switch_event_t *event = test_event((switch_event_types_t) id);
					int covered = 0;
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "x", "a");
					for (p = 0; p < count; p++) {
						if (plan[p].event_id == SWITCH_EVENT_ALL || plan[p].event_id == id) covered = 1;
					}
					fst_check(!mod_amqp_filter_match(engine, event) || covered);
					switch_event_destroy(&event);
				}
				mod_amqp_filter_engine_destroy(&engine);
			}
			fst_check(forbidden_external_calls == 0);
		}
		FST_TEST_END()
	}
	FST_SUITE_END()
	}
	switch_core_destroy();
}
FST_END()
