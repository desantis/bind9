# SUBDIRS = dlzexternal dyndb pipelined rndc rpz rsabigexponent tkey

#	@CHECKDS@ @COVERAGE@ @KEYMGR@ @DNSTAP@

SUBDIRS = dyndb/driver

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h		\
	-I$(top_srcdir)/lib/isc/unix/include		\
	-I$(top_srcdir)/lib/isc/pthreads/include	\
	-I$(top_srcdir)/lib/isc/include			\
	-I$(top_srcdir)/lib/dns/include

check_PROGRAMS =		\
	feature-test		\
	pipelined/pipequeries	\
	makejournal		\
	rndc/gencheck

feature_test_LDADD = \
	$(top_builddir)/lib/libisc.la

pipelined_pipequeries_LDADD =		\
	$(top_builddir)/lib/libisc.la	\
	$(top_builddir)/lib/libdns.la

makejournal_LDADD =			\
	$(top_builddir)/lib/libisc.la	\
	$(top_builddir)/lib/libdns.la

TESTS = \
	rpzrecurse serve-stale dnssec \
	acl additional addzone allow-query auth autosign \
	builtin cacheclean case catz cds chain \
	checkconf checknames checkzone \
	cookie database digdelv dlv dlz dlzexternal \
	dns64 dscp dsdigest dyndb \
	ednscompliance emptyzones \
	fetchlimit filter-aaaa formerr forward \
	geoip glue idna inline integrity ixfr keepalive \
	legacy limits logfileconfig \
	masterfile masterformat metadata mirror mkeys \
	names notify nslookup nsupdate nzd2nzf \
	padding pending pipelined qmin \
	reclimit redirect resolver rndc rootkeysentinel rpz \
	rrchecker rrl rrsetorder rsabigexponent runtime \
	sfcache smartsign sortlist \
	spf staticstub statistics statschannel stub synthfromdnssec \
	tcp tools tsig tsiggss \
	unknown upforwd verify views wildcard \
	xfer xferquota zero zonechecks

LOG_COMPILER = ./system-test-driver.sh
