include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_speechkit
if HAVE_KS

mod_LTLIBRARIES = mod_speechkit.la
mod_speechkit_la_SOURCES  = mod_speechkit.c
mod_speechkit_la_CFLAGS   = $(AM_CFLAGS) $(KS_CFLAGS)
mod_speechkit_la_LIBADD   = $(switch_builddir)/libfreeswitch.la $(KS_LIBS)
mod_speechkit_la_LDFLAGS  = -avoid-version -module -no-undefined -shared

endif
