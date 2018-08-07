ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I$(srcdir)/include/			\
	-I$(srcdir)/unix/include		\
	-I$(top_srcdir)/lib/isc/unix/include	\
	-I$(top_srcdir)/lib/isc/pthreads/include\
	-I$(top_srcdir)/lib/isc/include		\
	-I$(top_srcdir)/lib/isccc/include	\
	-I$(top_srcdir)/lib/dns/include		\
	-I$(top_srcdir)/lib/isccfg/include	\
	-I$(top_srcdir)/lib/irs/include		\
	-I$(top_srcdir)/lib/bind9/include	\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	-DSYSCONFDIR=\"${sysconfdir}\"

LDADD =				\
	${top_builddir}/lib/libbind9.la \
	${top_builddir}/lib/libisc.la \
	${top_builddir}/lib/libirs.la	\
	${top_builddir}/lib/libdns.la	\
	${top_builddir}/lib/libisccfg.la

bin_PROGRAMS =			\
	arpaname		\
	named-journalprint	\
	named-rrchecker		\
	nsec3hash		\
	mdig

if HAVE_DNSTAP
bin_PROGRAMS +=			\
	dnstap-read

dnstap_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(DNSTAP_CFLAGS)

dnstap_read_LDADD =		\
	$(LDADD)		\
	$(DNSTAP_LIBS)
endif

if HAVE_LMDB
bin_PROGRAMS +=			\
	named-nzd2nzf
endif
