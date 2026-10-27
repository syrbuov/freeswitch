include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_amqp

if HAVE_AMQP

mod_LTLIBRARIES = mod_amqp.la
mod_amqp_la_SOURCES  = mod_amqp_utils.c mod_amqp_connection.c mod_amqp_producer.c mod_amqp_command.c mod_amqp_logging.c mod_amqp.c
mod_amqp_la_SOURCES += mod_amqp_filter_parser.c mod_amqp_filter_compiler.c mod_amqp_filter_matcher.c mod_amqp_filter.h mod_amqp_filter_internal.h
mod_amqp_la_CFLAGS   = $(AM_CFLAGS) $(AMQP_CFLAGS)
mod_amqp_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_amqp_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(AMQP_LIBS) $(SWITCH_AM_LDFLAGS)

noinst_LTLIBRARIES = test/mod_amqp_api_reply_proxy.la
test_mod_amqp_api_reply_proxy_la_SOURCES = test/api_reply_proxy.c
test_mod_amqp_api_reply_proxy_la_CFLAGS = $(AM_CFLAGS)
test_mod_amqp_api_reply_proxy_la_LDFLAGS = -avoid-version -module -shared -rpath $(abs_builddir)/test/.libs

check_PROGRAMS = test/test_producer_lifecycle test/test_filter_engine test/test_producer_integration
TESTS = $(check_PROGRAMS)
test_test_producer_lifecycle_SOURCES = mod_amqp_filter_parser.c mod_amqp_filter_compiler.c mod_amqp_filter_matcher.c test/test_producer_lifecycle.c mod_amqp.c mod_amqp_utils.c mod_amqp_connection.c mod_amqp_command.c mod_amqp_logging.c
test_test_producer_lifecycle_CFLAGS = $(AM_CFLAGS) $(AMQP_CFLAGS) -I$(srcdir) \
  -DSWITCH_TEST_BASE_DIR_FOR_CONF=\"$(abs_srcdir)/test\" \
  -DSWITCH_TEST_BASE_DIR_OVERRIDE=\"$(abs_builddir)/test\"
test_test_producer_lifecycle_LDADD = $(switch_builddir)/libfreeswitch.la $(AMQP_LIBS)
test_test_producer_lifecycle_LDFLAGS = $(AM_LDFLAGS) -no-undefined
test_test_filter_engine_SOURCES = test/test_filter_engine.c
test_test_filter_engine_CFLAGS = $(AM_CFLAGS) -I$(srcdir) \
  -DSWITCH_TEST_BASE_DIR_FOR_CONF=\"$(abs_srcdir)/test\" \
  -DSWITCH_TEST_BASE_DIR_OVERRIDE=\"$(abs_builddir)/test\"
test_test_filter_engine_LDADD = $(switch_builddir)/libfreeswitch.la
test_test_filter_engine_LDFLAGS = $(AM_LDFLAGS) -no-undefined
test_test_producer_integration_SOURCES = test/test_producer_integration.c test/producer_integration_helpers.h test/producer_integration_cases.h mod_amqp_connection.c mod_amqp_filter_parser.c mod_amqp_filter_compiler.c mod_amqp_filter_matcher.c
test_test_producer_integration_CFLAGS = $(test_test_producer_lifecycle_CFLAGS)
test_test_producer_integration_CFLAGS += -DMOD_AMQP_API_PROXY_DIR=\"$(abs_builddir)/test/.libs\"
test_test_producer_integration_DEPENDENCIES = test/mod_amqp_api_reply_proxy.la
test_test_producer_integration_LDADD = $(test_test_producer_lifecycle_LDADD)
test_test_producer_integration_LDFLAGS = $(test_test_producer_lifecycle_LDFLAGS) -ldl
EXTRA_DIST = test/conf/freeswitch.xml test/README.md test/run_filter_engine_sanitizers.sh test/api_reply_cases.h test/api_reply_helpers.h

else
install: error
all: error
error:
	$(error You must install librabbitmq1 and librabbitmq-dev to build this module)
endif
