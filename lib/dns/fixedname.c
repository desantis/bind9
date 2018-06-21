/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <dns/fixedname.h>

#undef dns_fixedname_init
#undef dns_fixedname_invalidate
#undef dns_fixedname_name
#undef dns_fixedname_initname

void
dns_fixedname_init(dns_fixedname_t *fixed);
void
dns_fixedname_invalidate(dns_fixedname_t *fixed);
dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed);
dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed);

void
dns_fixedname_init(dns_fixedname_t *fixed) {
	dns_name_init(&fixed->name, fixed->offsets);
	isc_buffer_init(&fixed->buffer, fixed->data, DNS_NAME_MAXWIRE);
	dns_name_setbuffer(&fixed->name, &fixed->buffer);
}

void
dns_fixedname_invalidate(dns_fixedname_t *fixed) {
	dns_name_invalidate(&fixed->name);
}

dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed) {
	return (&fixed->name);
}

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed) {
	dns_fixedname_init(fixed);
	return (dns_fixedname_name(fixed));
}
