AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I../../isc/unix/include		\
	-I../../isc/pthreads/include		\
	-I../../isc/include			\
	-I../../dns/include			\
	-I../../isccfg/include			\
	-DTESTS=\"$(abs_srcdir)\"		\
	-DNAMED_PLUGINDIR=\"$(libdir)/named\"	\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	$(CMOCKA_CFLAGS)

AM_LDFLAGS = \
	../../libisc.la	\
	../../libdns.la \
	../../libiscfg.la \
	$(OPENSSL_LIBS)	\
	$(CMOCKA_LIBS)

check_PROGRAMS = \
	parser_test

TESTS = $(check_PROGRAMS)
