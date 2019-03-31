ISC
Internet Systems Consortium, Inc.
pkcs11-list
8
BIND9
pkcs11-list
list PKCS#11 objects
2009
2014
2015
2016
2018
2019
Internet Systems Consortium, Inc. ("ISC")
pkcs11-list
-P
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
DESCRIPTION
===========

``pkcs11-list`` lists the PKCS#11 objects with ``ID`` or ``label`` or by
default all objects. The object class, label, and ID are displayed for
all keys. For private or secret keys, the extractability attribute is
also displayed, as either ``true``, ``false``, or ``never``.

ARGUMENTS
=========

-P
   List only the public objects. (Note that on some PKCS#11 devices, all
   objects are private.)

-m module
   Specify the PKCS#11 provider module. This must be the full path to a
   shared library object implementing the PKCS#11 API for the device.

-s slot
   Open the session with the given PKCS#11 slot. The default is slot 0.

-i ID
   List only key objects with the given object ID.

-l label
   List only key objects with the given label.

-p PIN
   Specify the PIN for the device. If no PIN is provided on the command
   line, ``pkcs11-list`` will prompt for it.

SEE ALSO
========

pkcs11-destroy8, pkcs11-keygen8, pkcs11-tokens8
