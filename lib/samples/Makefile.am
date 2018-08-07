ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I$(top_srcdir)/lib/isc/unix/include	\
	-I$(top_srcdir)/lib/isc/pthreads/include	\
	-I$(top_srcdir)/lib/isc/include		\
	-I$(top_srcdir)/lib/dns/include		\
	-I$(top_srcdir)/lib/irs/include		\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)

noinst_PROGRAMS = 	\
	resolve		\
	sample-async	\
	sample-gai	\
	sample-update	\
	sample-request	\
	nsprobe

resolve_SOURCES = resolve.c
resolve_LDADD = ../libisc.la ../libirs.la ../libdns.la

sample_async_SOURCES = sample-async.c
sample_async_LDADD = ../libisc.la ../libdns.la

sample_gai_SOURCES = sample-gai.c
sample_gai_LDADD = ../libirs.la

sample_update_SOURCES = sample-update.c
sample_update_LDADD = ../libisc.la ../libdns.la

sample_request_SOURCES = sample-request.c
sample_request_LDADD = ../libisc.la ../libdns.la

nsprobe_SOURCES = nsprobe.c
nsprobe_LDADD = ../libisc.la ../libdns.la
