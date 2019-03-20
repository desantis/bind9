do_subst = \
	$(SED) -e 's,[@]PYTHON[@],$(PYTHON),g' \
	       -e 's,[@]PYTHON_INSTALL_DIR[@],$(PYTHON_INSTALL_DIR),g' \
	       -e 's,[@]prefix[@],$(prefix),g' \
	       -e 's,[@]sysconfdir[@],$(sysconfdir),g'

EXTRA_DIST = 			\
	isc/utils.py		\
	dnssec-checkds.py	\
	dnssec-coverage.py	\
	dnssec-keymgr.py

BUILT_SOURCES =			\
	isc/utils.py

isc/utils.py: isc/utils.py.in
	$(do_subst) < $< > $@

dnssec-checkds: dnssec-checkds.py.in
	$(do_subst) < $< > $@
	chmod +x $@

dnssec-coverage: dnssec-coverage.py.in
	$(do_subst) < $< > $@
	chmod +x $@

dnssec-keymgr: dnssec-keymgr.py.in
	$(do_subst) < $< > $@
	chmod +x $@

python_PYTHON =			\
	isc/__init__.py		\
	isc/checkds.py		\
	isc/coverage.py		\
	isc/dnskey.py		\
	isc/eventlist.py	\
	isc/keydict.py		\
	isc/keyevent.py		\
	isc/keymgr.py		\
	isc/keyseries.py	\
	isc/keyzone.py		\
	isc/policy.py		\
	isc/rndc.py		\
	isc/utils.py

bin_SCRIPTS =			\
	dnssec-checkds		\
	dnssec-coverage		\
	dnssec-keymgr

CLEANFILES =			\
	$(BUILT_SOURCES)	\
	$(bin_SCRIPTS)
