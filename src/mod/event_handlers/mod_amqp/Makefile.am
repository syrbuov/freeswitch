include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_amqp

if HAVE_AMQP

mod_LTLIBRARIES = mod_amqp.la
mod_amqp_la_SOURCES  = mod_amqp_utils.c mod_amqp_connection.c mod_amqp_producer.c mod_amqp_command.c mod_amqp_logging.c mod_amqp.c
mod_amqp_la_CFLAGS   = $(AM_CFLAGS) $(AMQP_CFLAGS)
mod_amqp_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_amqp_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(AMQP_LIBS) $(SWITCH_AM_LDFLAGS)

check_PROGRAMS = test/test_producer_lifecycle
TESTS = $(check_PROGRAMS)
test_test_producer_lifecycle_SOURCES = test/test_producer_lifecycle.c mod_amqp.c mod_amqp_utils.c mod_amqp_connection.c mod_amqp_command.c mod_amqp_logging.c
test_test_producer_lifecycle_CFLAGS = $(AM_CFLAGS) $(AMQP_CFLAGS) -I$(srcdir) \
  -DSWITCH_TEST_BASE_DIR_FOR_CONF=\"$(abs_srcdir)/test\" \
  -DSWITCH_TEST_BASE_DIR_OVERRIDE=\"$(abs_builddir)/test\"
test_test_producer_lifecycle_LDADD = $(switch_builddir)/libfreeswitch.la $(AMQP_LIBS)
test_test_producer_lifecycle_LDFLAGS = $(AM_LDFLAGS) -no-undefined
EXTRA_DIST = test/conf/freeswitch.xml test/README.md

else
install: error
all: error
error:
	$(error You must install librabbitmq1 and librabbitmq-dev to build this module)
endif
