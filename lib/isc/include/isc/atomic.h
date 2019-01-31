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

#pragma once

#if HAVE_STDATOMIC_H
#include <stdatomic.h>
#else
#include <isc/stdatomic.h>
#endif

/*
 * We define a few additional macros to make things easier
 */

#define atomic_store_relaxed(obj, desired) \
	atomic_store_explicit((obj), (desired), memory_order_relaxed)

#define atomic_load_relaxed(obj) \
	atomic_load_explicit((obj), memory_order_relaxed)

#define atomic_fetch_add_relaxed(obj, arg) \
	atomic_fetch_add_explicit((obj), (arg), memory_order_relaxed)

#define atomic_fetch_sub_relaxed(obj, arg) \
	atomic_fetch_sub_explicit((obj), (arg), memory_order_relaxed)

#define atomic_compare_exchange_strong_relaxed(obj, expected, desired) \
	atomic_compare_exchange_strong_explicit((obj), (expected), (desired), \
						memory_order_relaxed,	\
						memory_order_relaxed)

#define atomic_compare_exchange_weak_relaxed(obj, expected, desired)	\
	atomic_compare_exchange_weak_explicit((obj), (expected), (desired), \
					      memory_order_relaxed,	\
					      memory_order_relaxed)
