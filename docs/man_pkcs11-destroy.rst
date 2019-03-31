ISC
Internet Systems Consortium, Inc.
pkcs11-destroy
8
BIND9
pkcs11-destroy
destroy PKCS#11 objects
2009
2014
2015
2016
2018
2019
Internet Systems Consortium, Inc. ("ISC")
pkcs11-destroy
-m
module
-s
slot
-i
ID
-l
label
-p
PIN
-w
seconds
DESCRIPTION
===========

``pkcs11-destroy`` destroys keys stored in a PKCS#11 device, identified
by their ``ID`` or ``label``.

Matching keys are displayed before being destroyed. By default, there is
a five second delay to allow the user to interrupt the process before
the destruction takes place.

ARGUMENTS
=========

-m module
   Specify the PKCS#11 provider module. This must be the full path to a
   shared library object implementing the PKCS#11 API for the device.

-s slot
   Open the session with the given PKCS#11 slot. The default is slot 0.

-i ID
   Destroy keys with the given object ID.

-l label
   Destroy keys with the given label.

-p PIN
   Specify the PIN for the device. If no PIN is provided on the command
   line, ``pkcs11-destroy`` will prompt for it.

-w seconds
   Specify how long to pause before carrying out key destruction. The
   default is five seconds. If set to ``0``, destruction will be
   immediate.

SEE ALSO
========

pkcs11-keygen8, pkcs11-list8, pkcs11-tokens8
