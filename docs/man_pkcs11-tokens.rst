ISC
Internet Systems Consortium, Inc.
pkcs11-tokens
8
BIND9
pkcs11-tokens
list PKCS#11 available tokens
2014
2015
2016
2018
2019
Internet Systems Consortium, Inc. ("ISC")
pkcs11-tokens
-m
module
-v
DESCRIPTION
===========

``pkcs11-tokens`` lists the PKCS#11 available tokens with defaults from
the slot/token scan performed at application initialization.

ARGUMENTS
=========

-m module
   Specify the PKCS#11 provider module. This must be the full path to a
   shared library object implementing the PKCS#11 API for the device.

-v
   Make the PKCS#11 libisc initialization verbose.

SEE ALSO
========

pkcs11-destroy8, pkcs11-keygen8, pkcs11-list8
