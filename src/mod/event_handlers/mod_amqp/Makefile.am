include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_amqp

if HAVE_AMQP

mod_LTLIBRARIES = mod_amqp.la
mod_amqp_la_SOURCES  = mod_amqp_utils.c mod_amqp_connection.c mod_amqp_producer.c mod_amqp_command.c mod_amqp_logging.c mod_amqp.c
mod_amqp_la_SOURCES += mod_amqp_filter_parser.c mod_amqp_filter_compiler.c mod_amqp_filter_matcher.c mod_amqp_filter.h mod_amqp_filter_internal.h
mod_amqp_la_CFLAGS   = $(AM_CFLAGS) $(AMQP_CFLAGS)
mod_amqp_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_amqp_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(AMQP_LIBS) $(SWITCH_AM_LDFLAGS)

# A regenerated dummy .Plo must not leave an old object using the previous
# layout of mod_amqp_globals or profile structs after mod_amqp.h changes.
$(mod_amqp_la_OBJECTS): $(srcdir)/mod_amqp.h

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
test_test_producer_integration_SOURCES = test/test_producer_integration.c test/producer_integration_helpers.h test/producer_integration_cases.h test/worker_loop_helpers.h test/worker_loop_cases.h mod_amqp_connection.c mod_amqp_filter_parser.c mod_amqp_filter_compiler.c mod_amqp_filter_matcher.c
test_test_producer_integration_CFLAGS = $(test_test_producer_lifecycle_CFLAGS)
test_test_producer_integration_CFLAGS += -DMOD_AMQP_API_PROXY_DIR=\"$(abs_builddir)/test/.libs\"
test_test_producer_integration_DEPENDENCIES = test/mod_amqp_api_reply_proxy.la
test_test_producer_integration_LDADD = $(test_test_producer_lifecycle_LDADD)
test_test_producer_integration_LDFLAGS = $(test_test_producer_lifecycle_LDFLAGS) -ldl

# These production sources are deliberately included into test translation
# units so the fixtures can wrap selected calls.  State the edges explicitly:
# an existing or freshly generated dependency file must not decide whether a
# changed implementation is picked up by an ordinary make check.
test/test_filter_engine-test_filter_engine.$(OBJEXT): \
  $(srcdir)/mod_amqp_filter_parser.c $(srcdir)/mod_amqp_filter_compiler.c \
  $(srcdir)/mod_amqp_filter_matcher.c $(srcdir)/mod_amqp_filter.h \
  $(srcdir)/mod_amqp_filter_internal.h
test/test_producer_lifecycle-test_producer_lifecycle.$(OBJEXT): \
  $(srcdir)/mod_amqp_producer.c $(srcdir)/mod_amqp.h
test/test_producer_integration-test_producer_integration.$(OBJEXT): \
  $(srcdir)/test/test_producer_lifecycle.c $(srcdir)/mod_amqp_producer.c \
  $(srcdir)/mod_amqp_utils.c $(srcdir)/mod_amqp.c \
  $(srcdir)/mod_amqp_logging.c $(srcdir)/mod_amqp_command.c \
  $(srcdir)/test/api_reply_helpers.h $(srcdir)/test/api_reply_cases.h \
  $(srcdir)/test/producer_integration_helpers.h \
  $(srcdir)/test/producer_integration_cases.h \
  $(srcdir)/test/worker_loop_helpers.h $(srcdir)/test/worker_loop_cases.h \
  $(srcdir)/mod_amqp.h
EXTRA_DIST = test/conf/freeswitch.xml test/README.md test/run_filter_engine_sanitizers.sh test/api_reply_cases.h test/api_reply_helpers.h
EXTRA_DIST += test/lifecycle_probe.c test/lifecycle_probe_interposer.c test/run_lifecycle_probes.py test/asan_thread_exit_repro.c

else
install: error
all: error
error:
	$(error You must install librabbitmq1 and librabbitmq-dev to build this module)
endif
