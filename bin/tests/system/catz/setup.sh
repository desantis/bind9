#!/bin/sh
#
# Copyright (C) 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

copy_setports ns1/named.conf.in ns1/named.conf
copy_setports ns2/named.conf.in ns2/named.conf
copy_setports ns3/named.conf.in ns3/named.conf

cp -f ns1/catalog.example.db.in ns1/catalog1.example.db
cp -f ns1/catalog.example.db.in ns3/catalog2.example.db
cp -f ns1/catalog.example.db.in ns1/catalog3.example.db
cp -f ns1/catalog.example.db.in ns1/catalog4.example.db

mkdir -p ns2/zonedir
