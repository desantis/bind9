AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I../../isc//unix/include		\
	-I../../isc/pthreads/include		\
	-I../../isc/include			\
	-I../../dns/include			\
	-DTESTS=\"$(abs_srcdir)\"		\
	$(OPENSSL_CFLAGS)			\
	$(OPENSSL_INCLUDES)			\
	$(CMOCKA_CFLAGS)

AM_LDFLAGS = \
	../../libisc.la		\
	../../libdns.la		\
	libdnstest.la		\
	$(OPENSSL_LIBS)		\
	$(CMOCKA_LIBS)

noinst_LTLIBRARIES = libdnstest.la
libdnstest_la_SOURCES = dnstest.c dnstest.h
libdnstest_la_LDFLAGS =

check_PROGRAMS = \
	acl_test \
	db_test \
	dbdiff_test \
	dbiterator_test \
	dbversion_test \
	dh_test \
	dispatch_test \
	dnstap_test \
	dst_test \
	geoip_test \
	keytable_test \
	master_test \
	name_test \
	nsec3_test \
	peer_test \
	private_test \
	rbt_serialize_test \
	rbt_test \
	rdata_test \
	rdataset_test \
	rdatasetstats_test \
	resolver_test \
	result_test \
	rsa_test \
	sigs_test \
	time_test \
	tkey_test \
	tsig_test \
	update_test \
	zonemgr_test \
	zt_test

TESTS = $(check_PROGRAMS)

EXTRA_master_test_DEPENDENCIES = testdata/master/master12.data testdata/master/master13.data testdata/master/master14.data

testdata/master/master12.data: testdata/master/master12.data.in
	$(PERL) -w $(srcdir)/mkraw.pl < $< > $@

testdata/master/master13.data: testdata/master/master13.data.in
	$(PERL) -w $(srcdir)/mkraw.pl < $< > $@

testdata/master/master14.data: testdata/master/master14.data.in
	$(PERL) -w $(srcdir)/mkraw.pl < $< > $@

CLEANFILES = $(EXTRA_master_test_DEPENDENCIES)
