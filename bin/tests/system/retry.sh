#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Creates the system tests output file from the various test.output files.  It
# then searches that file and prints the number of tests passed, failed, not
# run.  It also checks whether the IP addresses 10.53.0.[1-8] were set up and,
# if not, prints a warning.
#
# Usage:
#    retry.sh
#
# Status return:
# 0 - no tests failed
# 1 - one or more tests failed

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

numproc=${1:-1}

if [ ! -f systests.output ]; then
    echofail "I:'systests.output' not found."
    exit 0
fi

status=0
grep 'R:[a-z0-9_-][a-z0-9_-]*:[A-Z][A-Z]*' systests.output | \
    awk -F: 'START { print ". ./conf.sh" }
        $1 == "R" && $3 == "FAIL" { retests = retests " test-"$2; }
        END { if (retests) { print "make -f parallel.mk -j " retests } }' | \
    sed -e "s/NUMPROC/$numproc/" | \
    $SHELL
$SHELL testsummary.sh
