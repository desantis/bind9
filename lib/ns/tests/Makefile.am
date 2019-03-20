AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I../../isc/unix/include		\
	-I../../isc/pthreads/include		\
	-I../../isc/include			\
	-I../../dns/include			\
	-I../../ns/include			\
	-DTESTS=\"$(abs_srcdir)\"		\
	-DNAMED_PLUGINDIR=\"$(libdir)/named\"	\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	$(CMOCKA_CFLAGS)

AM_LDFLAGS = \
	../../libisc.la	\
	../../libdns.la \
	../../libns.la \
	libnstest.la \
	$(OPENSSL_LIBS)	\
	$(CMOCKA_LIBS)

noinst_LTLIBRARIES = libnstest.la
libnstest_la_SOURCES = nstest.c nstest.h
libnstest_la_LDFLAGS =

check_PROGRAMS = \
	listenlist_test \
	notify_test \
	plugin_test \
	query_test

TESTS = $(check_PROGRAMS)
