AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I../../isc/unix/include		\
	-I../../isc/pthreads/include		\
	-I../../isc/include			\
	-I../../dns/include			\
	-I../../irs/include			\
	-DTESTS=\"$(abs_srcdir)\"		\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	$(CMOCKA_CFLAGS)

AM_LDFLAGS = \
	../../libisc.la	\
	../../libdns.la \
	../../libirs.la \
	$(OPENSSL_LIBS)	\
	$(CMOCKA_LIBS)

check_PROGRAMS = \
	resconf_test

TESTS = $(check_PROGRAMS)
