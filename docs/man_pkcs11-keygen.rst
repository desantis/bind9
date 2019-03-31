ISC
Internet Systems Consortium, Inc.
pkcs11-keygen
8
BIND9
pkcs11-keygen
generate keys on a PKCS#11 device
2009
2014
2015
2016
2017
2018
2019
Internet Systems Consortium, Inc. ("ISC")
pkcs11-keygen
-a
algorithm
-b
keysize
-e
-i
id
-m
module
-P
-p
PIN
-q
-S
-s
slot
label
DESCRIPTION
===========

``pkcs11-keygen`` causes a PKCS#11 device to generate a new key pair
with the given ``label`` (which must be unique) and with ``keysize``
bits of prime.

ARGUMENTS
=========

-a algorithm
   Specify the key algorithm class: Supported classes are RSA, DSA, DH,
   ECC and ECX. In addition to these strings, the ``algorithm`` can be
   specified as a DNSSEC signing algorithm that will be used with this
   key; for example, NSEC3RSASHA1 maps to RSA, ECDSAP256SHA256 maps to
   ECC, and ED25519 to ECX. The default class is "RSA".

-b keysize
   Create the key pair with ``keysize`` bits of prime. For ECC keys, the
   only valid values are 256 and 384, and the default is 256. For ECX
   kyes, the only valid values are 256 and 456, and the default is 256.

-e
   For RSA keys only, use a large exponent.

-i id
   Create key objects with id. The id is either an unsigned short 2 byte
   or an unsigned long 4 byte number.

-m module
   Specify the PKCS#11 provider module. This must be the full path to a
   shared library object implementing the PKCS#11 API for the device.

-P
   Set the new private key to be non-sensitive and extractable. The
   allows the private key data to be read from the PKCS#11 device. The
   default is for private keys to be sensitive and non-extractable.

-p PIN
   Specify the PIN for the device. If no PIN is provided on the command
   line, ``pkcs11-keygen`` will prompt for it.

-q
   Quiet mode: suppress unnecessary output.

-S
   For Diffie-Hellman (DH) keys only, use a special prime of 768, 1024
   or 1536 bit size and base (aka generator) 2. If not specified, bit
   size will default to 1024.

-s slot
   Open the session with the given PKCS#11 slot. The default is slot 0.

SEE ALSO
========

pkcs11-destroy8, pkcs11-list8, pkcs11-tokens8, dnssec-keyfromlabel8
