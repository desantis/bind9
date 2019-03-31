# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'BIND 9'
copyright = '2019, Internet Systems Consortium'
author = 'Internet Systems Consortium'

# The full version, including alpha/beta/rc tags
release = '9.15-dev'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'
html_theme_path = ["_themes", ]

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

man_pages = [
	('man_arpaname', 'arpaname', '', 'Internet Systems Consortium', 1),
	('man_ddns-confgen', 'ddns-confgen', '', 'Internet Systems Consortium', 1),
	('man_delv', 'delv', '', 'Internet Systems Consortium', 1),
	('man_dig', 'dig', '', 'Internet Systems Consortium', 1),
	('man_dnssec-cds', 'dnssec-cds', '', 'Internet Systems Consortium', 1),
	('man_dnssec-checkds', 'dnssec-checkds', '', 'Internet Systems Consortium', 1),
	('man_dnssec-coverage', 'dnssec-coverage', '', 'Internet Systems Consortium', 1),
	('man_dnssec-dsfromkey', 'dnssec-dsfromkey', '', 'Internet Systems Consortium', 1),
	('man_dnssec-importkey', 'dnssec-importkey', '', 'Internet Systems Consortium', 1),
	('man_dnssec-keyfromlabel', 'dnssec-keyfromlabel', '', 'Internet Systems Consortium', 1),
	('man_dnssec-keygen', 'dnssec-keygen', '', 'Internet Systems Consortium', 1),
	('man_dnssec-keymgr', 'dnssec-keymgr', '', 'Internet Systems Consortium', 1),
	('man_dnssec-revoke', 'dnssec-revoke', '', 'Internet Systems Consortium', 1),
	('man_dnssec-settime', 'dnssec-settime', '', 'Internet Systems Consortium', 1),
	('man_dnssec-signzone', 'dnssec-signzone', '', 'Internet Systems Consortium', 1),
	('man_dnssec-verify', 'dnssec-verify', '', 'Internet Systems Consortium', 1),
	('man_dnstap-read', 'dnstap-read', '', 'Internet Systems Consortium', 1),
	('man_filter-aaaa', 'filter-aaaa', '', 'Internet Systems Consortium', 1),
	('man_host', 'host', '', 'Internet Systems Consortium', 1),
	('man_mdig', 'mdig', '', 'Internet Systems Consortium', 1),
	('man_named-checkconf', 'named-checkconf', '', 'Internet Systems Consortium', 1),
	('man_named-checkzone', 'named-checkzone', '', 'Internet Systems Consortium', 1),
	('man_named-journalprint', 'named-journalprint', '', 'Internet Systems Consortium', 1),
	('man_named-nzd2nzf', 'named-nzd2nzf', '', 'Internet Systems Consortium', 1),
	('man_named-rrchecker', 'named-rrchecker', '', 'Internet Systems Consortium', 1),
	('man_named.conf', 'named.conf', '', 'Internet Systems Consortium', 1),
	('man_named', 'named', '', 'Internet Systems Consortium', 1),
	('man_nsec3hash', 'nsec3hash', '', 'Internet Systems Consortium', 1),
	('man_nslookup', 'nslookup', '', 'Internet Systems Consortium', 1),
	('man_nsupdate', 'nsupdate', '', 'Internet Systems Consortium', 1),
	('man_pkcs11-destroy', 'pkcs11-destroy', '', 'Internet Systems Consortium', 1),
	('man_pkcs11-keygen', 'pkcs11-keygen', '', 'Internet Systems Consortium', 1),
	('man_pkcs11-list', 'pkcs11-list', '', 'Internet Systems Consortium', 1),
	('man_pkcs11-tokens', 'pkcs11-tokens', '', 'Internet Systems Consortium', 1),
	('man_rndc-confgen', 'rndc-confgen', '', 'Internet Systems Consortium', 1),
	('man_rndc.conf', 'rndc.conf', '', 'Internet Systems Consortium', 1),
	('man_rndc', 'rndc', 'name server control utility', 'Internet Systems Consortium', 8)
]
