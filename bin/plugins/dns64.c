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

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/lib.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/print.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/grammar.h>

#include <ns/client.h>
#include <ns/hooks.h>
#include <ns/interfacemgr.h>
#include <ns/log.h>
#include <ns/query.h>
#include <ns/types.h>

#include <dns/db.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/rdatalist.h>
#include <dns/result.h>
#include <dns/sdb.h>
#include <dns/types.h>
#include <dns/view.h>
#include <dns/zone.h>

#define CHECK(op)						\
	do {							\
		result = (op);					\
		if (result != ISC_R_SUCCESS) {			\
			goto cleanup;				\
		}						\
	} while (0)

#define QUERY_ERROR(qctx, r) \
do { \
	qctx->result = r; \
	qctx->want_restart = false; \
	qctx->line = __LINE__; \
} while (0)

#define SAVE(a, b) do { INSIST(a == NULL); a = b; b = NULL; } while (0)
#define RESTORE(a, b) SAVE(a, b)

/**
 ** Types
 **/
typedef struct dns64 dns64_t;
struct dns64 {
	unsigned char bits[16];		/* prefix + suffix bits */
	dns_acl_t *clients;		/* which clients get mapped
					 * addresses */
	dns_acl_t *mapped;		/* v4 addresses to be mapped */
	dns_acl_t *excluded;		/* v6 addresses that are
					 * treated as not existing */
	unsigned int prefixlen;		/* start of mapped address */
	unsigned int flags;
	isc_mem_t *mctx;
	ISC_LINK(dns64_t) link;
};

typedef ISC_LIST(dns64_t)			dns64list_t;

/*!
 * Flags for use with dns64_createentry()
 */
typedef enum {
	RECURSIVE_ONLY = 0x01,	/* Record only applies to recursive queries */
	BREAK_DNSSEC   = 0x02,	/* Synthesize even if it breaks validation */
} dns64_createflags_t;

/*!
 * Flags for use with dns64_checkaaaa() and dns64_aaaafroma()
 */
typedef enum {
	RECURSIVE = 0x01,	/* Recursive query */
	DNSSEC    = 0x02,	/* DNSSEC sensitive query */
} dns64_flags_t;

/*
 * Client attribute tests.
 */
/*% Recursion OK? */
#define RECURSIONOK(c)		(((c)->query.attributes & \
				  NS_QUERYATTR_RECURSIONOK) != 0)
/*% Want DNSSEC? */
#define WANTDNSSEC(c)		(((c)->attributes & \
				  NS_CLIENTATTR_WANTDNSSEC) != 0)

/*
 * Persistent data for use by this module. This will be associated
 * with client object address in the hash table, and will remain
 * accessible until the client object is detached.
 */

typedef struct dns64_data {
	dns_rdataset_t *aaaa;
	dns_rdataset_t *sigaaaa;
	bool *aaaaok;
	unsigned int aaaaoklen;
	unsigned int ttl;
	unsigned int flags;
	bool dns64;
	bool dns64_exclude;
} dns64_data_t;

typedef struct dns64_instance {
	isc_mem_t *mctx;
	/*
	 * Memory pool for allocating persistent data blobs.
	 */
	isc_mempool_t *datapool;

	/*
	 * Hash table associating a client object with its persistent data.
	 */
	isc_ht_t *ht;

	dns_acl_t *dns64_mapped;
	dns64list_t dns64list;
	unsigned int dns64cnt;
} dns64_instance_t;

/*
 * SDB DNS64 database implementation.
 */
dns_sdbimplementation_t *dns64_impl = NULL;

/*
 * Increment when registering, decrement when shutting down, so we
 * can tear down the SDB implementation only on the last shutdown.
 */
static unsigned int registrations = 0;

static isc_result_t
dns64_createentry(isc_mem_t *mctx, const isc_netaddr_t *prefix,
		  unsigned int prefixlen, const isc_netaddr_t *suffix,
		  dns_acl_t *clients, dns_acl_t *mapped, dns_acl_t *excluded,
		  dns64_createflags_t flags, dns64_t **dns64p);

static void
dns64_destroyentry(dns64_t **dns64p);

static void
dns64_append(dns64list_t *list, dns64_t *dns64);

static void
dns64_unlink(dns64list_t *list, dns64_t *dns64);

static uint32_t
dns64_ttl(dns_db_t *db, dns_dbversion_t *version);

static bool
dns64_aaaaok(ns_client_t *client,
	     dns64_instance_t *inst, dns64_data_t *client_state,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset);

static isc_result_t
dns64_synth(query_ctx_t *qctx, dns64_instance_t *inst,
	    dns64_data_t *client_state);

static void
dns64_filter(query_ctx_t *qctx, dns64_data_t *client_state);

/*
 * Forward declarations of functions referenced in install_hooks().
 */
static ns_hookresult_t
dns64_qctx_initialize(void *arg, void *cbdata, isc_result_t *resp);
static ns_hookresult_t
dns64_respond_begin(void *arg, void *cbdata, isc_result_t *resp);
static ns_hookresult_t
dns64_addanswer(void *arg, void *cbdata, isc_result_t *resp);
static ns_hookresult_t
dns64_delegation_recurse(void *arg, void *cbdata, isc_result_t *resp);
static ns_hookresult_t
dns64_nodata_begin(void *arg, void *cbdata, isc_result_t *resp);
static ns_hookresult_t
dns64_qctx_destroy(void *arg, void *cbdata, isc_result_t *resp);

/*%
 * Register the functions to be called at each hook point in 'hooktable', using
 * memory context 'mctx' for allocating copies of stack-allocated structures
 * passed to ns_hook_add().  Make sure 'inst' will be passed as the 'cbdata'
 * argument to every callback.
 */
static void
install_hooks(ns_hooktable_t *hooktable, isc_mem_t *mctx,
	      dns64_instance_t *inst)
{
	const ns_hook_t dns64_init = {
		.action = dns64_qctx_initialize,
		.action_data = inst,
	};

	const ns_hook_t dns64_respbegin = {
		.action = dns64_respond_begin,
		.action_data = inst,
	};

	const ns_hook_t dns64_addanswerbegin = {
		.action = dns64_addanswer,
		.action_data = inst,
	};

	const ns_hook_t dns64_delrec = {
		.action = dns64_delegation_recurse,
		.action_data = inst,
	};

	const ns_hook_t dns64_nodata = {
		.action = dns64_nodata_begin,
		.action_data = inst,
	};

	const ns_hook_t dns64_destroy = {
		.action = dns64_qctx_destroy,
		.action_data = inst,
	};

	ns_hook_add(hooktable, mctx,
		    NS_QUERY_QCTX_INITIALIZED, &dns64_init);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_RESPOND_BEGIN, &dns64_respbegin);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_ADDANSWER_BEGIN, &dns64_addanswerbegin);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_DELEGATION_RECURSE_BEGIN, &dns64_delrec);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_NODATA_BEGIN, &dns64_nodata);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_QCTX_DESTROYED, &dns64_destroy);
}

/**
 ** Support for parsing of parameters and configuration of the module.
 **/
static cfg_clausedef_t
dns64_clauses[] = {
	{ "break-dnssec", &cfg_type_boolean, 0 },
	{ "clients", &cfg_type_bracketed_aml, 0 },
	{ "exclude", &cfg_type_bracketed_aml, 0 },
	{ "mapped", &cfg_type_bracketed_aml, 0 },
	{ "recursive-only", &cfg_type_boolean, 0 },
	{ "suffix", &cfg_type_netaddr6, 0 },
	{ NULL, NULL, 0 },
};

static cfg_clausedef_t *
dns64_clausesets[] = {
	dns64_clauses,
	NULL
};

static cfg_type_t cfg_type_dns64 = {
	"dns64", cfg_parse_netprefix_map, cfg_print_map,
	cfg_doc_map, &cfg_rep_map, dns64_clausesets
};

static cfg_clausedef_t param_clauses[] = {
	{ "dns64", &cfg_type_dns64, CFG_CLAUSEFLAG_MULTI },
	{ "dns64-contact", &cfg_type_astring, 0 },
	{ "dns64-server", &cfg_type_astring, 0 },
};

static cfg_clausedef_t *param_clausesets[] = {
	param_clauses,
	NULL
};

static cfg_type_t cfg_type_parameters = {
	"dns64-params", cfg_parse_mapbody, cfg_print_mapbody,
	cfg_doc_mapbody, &cfg_rep_map, param_clausesets
};

static isc_result_t
create_mapped_acl(isc_mem_t *mctx, dns_acl_t **aclp) {
	isc_result_t result;
	dns_acl_t *acl = NULL;
	struct in6_addr in6 = IN6ADDR_V4MAPPED_INIT;
	isc_netaddr_t addr;

	isc_netaddr_fromin6(&addr, &in6);

	result = dns_acl_create(mctx, 1, &acl);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	result = dns_iptable_addprefix(acl->iptable, &addr, 96, true);
	if (result == ISC_R_SUCCESS) {
		dns_acl_attach(acl, aclp);
	}

	dns_acl_detach(&acl);
	return (result);
}

static isc_result_t
dns64_reverse(dns_view_t *view, isc_log_t *lctx, isc_netaddr_t *na,
	      unsigned int prefixlen, const char *server,
	      const char *contact)
{
	isc_result_t result;
	char reverse[48+sizeof("ip6.arpa.")] = { 0 };
	char buf[sizeof("x.x.")];
	const char *dns64_dbtype[4] = { "_dns64", "dns64", ".", "." };
	const unsigned char *s6 = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	dns_zone_t *zone = NULL;
	int dns64_dbtypec = 4;
	isc_buffer_t b;

	REQUIRE(prefixlen == 32 || prefixlen == 40 || prefixlen == 48 ||
		prefixlen == 56 || prefixlen == 64 || prefixlen == 96);

	/*
	 * Construct the reverse name of the zone.
	 */
	s6 = na->type.in6.s6_addr;
	while (prefixlen > 0) {
		prefixlen -= 8;
		snprintf(buf, sizeof(buf), "%x.%x.", s6[prefixlen/8] & 0xf,
			 (s6[prefixlen/8] >> 4) & 0xf);
		strlcat(reverse, buf, sizeof(reverse));
	}
	strlcat(reverse, "ip6.arpa.", sizeof(reverse));

	/*
	 * Create the actual zone.
	 */
	if (server != NULL) {
		dns64_dbtype[2] = server;
	}

	if (contact != NULL) {
		dns64_dbtype[3] = contact;
	}

	name = dns_fixedname_initname(&fixed);
	isc_buffer_constinit(&b, reverse, strlen(reverse));
	isc_buffer_add(&b, strlen(reverse));
	CHECK(dns_name_fromtext(name, &b, dns_rootname, 0, NULL));
	CHECK(dns_zonemgr_createzone(view->zonemgr, &zone));
	CHECK(dns_zone_setorigin(zone, name));
	dns_zone_setview(zone, view);
	CHECK(dns_zonemgr_managezone(view->zonemgr, zone));
	dns_zone_setclass(zone, view->rdclass);
	dns_zone_settype(zone, dns_zone_master);

	CHECK(dns_zone_setdbtype(zone, dns64_dbtypec, dns64_dbtype));

	if (view->queryacl != NULL) {
		dns_zone_setqueryacl(zone, view->queryacl);
	}
	if (view->queryonacl != NULL) {
		dns_zone_setqueryonacl(zone, view->queryonacl);
	}

	dns_zone_setdialup(zone, dns_dialuptype_no);
	dns_zone_setnotifytype(zone, dns_notifytype_no);
	dns_zone_setoption(zone, DNS_ZONEOPT_NOCHECKNS, true);

	/*
	 * XXX this functionality will need to be restored:
	 *
	 * dns_zone_setstats(zone, server->zonestats);
	 * CHECK(setquerystats(zone, mctx, dns_zonestat_none));
	 */

	CHECK(dns_view_addzone(view, zone));
	isc_log_write(lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "dns64 reverse zone (view %s): %s",
		      view->name, reverse);

cleanup:
	if (zone != NULL) {
		dns_zone_detach(&zone);
	}

	return (result);
}

static isc_result_t
check_syntax(cfg_obj_t *dmap, const cfg_obj_t *cfg,
	     isc_mem_t *mctx, isc_log_t *lctx, void *actx)
{
	isc_result_t result = ISC_R_SUCCESS;
	static const unsigned char zeros[16];
	const cfg_obj_t *dns64 = NULL;
	const cfg_listelt_t *element;
	const cfg_obj_t *map, *obj;
	isc_netaddr_t na, sa;
	unsigned int prefixlen;
	int nbytes;
	int i;

	static const char *acls[] = { "clients", "exclude", "mapped", NULL};

	cfg_map_get(dmap, "dns64", &dns64);
	if (dns64 == NULL) {
		return (ISC_R_SUCCESS);
	}

	for (element = cfg_list_first(dns64);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		map = cfg_listelt_value(element);
		obj = cfg_map_getname(map);

		cfg_obj_asnetprefix(obj, &na, &prefixlen);
		if (na.family != AF_INET6) {
			cfg_obj_log(map, lctx, ISC_LOG_ERROR,
				    "dns64 requires an IPv6 prefix");
			result = ISC_R_FAILURE;
			continue;
		}

		if (prefixlen != 32 && prefixlen != 40 && prefixlen != 48 &&
		    prefixlen != 56 && prefixlen != 64 && prefixlen != 96)
		{
			cfg_obj_log(map, lctx, ISC_LOG_ERROR,
				    "bad prefix length %u [32/40/48/56/64/96]",
				    prefixlen);
			result = ISC_R_FAILURE;
			continue;
		}

		for (i = 0; acls[i] != NULL; i++) {
			obj = NULL;
			(void)cfg_map_get(map, acls[i], &obj);
			if (obj != NULL) {
				dns_acl_t *acl = NULL;
				isc_result_t tresult;

				tresult = cfg_acl_fromconfig(obj, cfg,
							     lctx, actx,
							     mctx, 0,
							     &acl);
				if (acl != NULL) {
					dns_acl_detach(&acl);
				}
				if (tresult != ISC_R_SUCCESS) {
					result = tresult;
				}
			}
		}

		obj = NULL;
		(void)cfg_map_get(map, "suffix", &obj);
		if (obj != NULL) {
			isc_netaddr_fromsockaddr(&sa, cfg_obj_assockaddr(obj));
			if (sa.family != AF_INET6) {
				cfg_obj_log(map, lctx, ISC_LOG_ERROR,
					    "dns64 requires a IPv6 suffix");
				result = ISC_R_FAILURE;
				continue;
			}
			nbytes = prefixlen / 8 + 4;
			if (prefixlen >= 32 && prefixlen <= 64) {
				nbytes++;
			}
			if (memcmp(sa.type.in6.s6_addr, zeros, nbytes) != 0) {
				char netaddrbuf[ISC_NETADDR_FORMATSIZE];
				isc_netaddr_format(&sa, netaddrbuf,
						   sizeof(netaddrbuf));
				cfg_obj_log(obj, lctx, ISC_LOG_ERROR,
					    "bad suffix '%s' leading "
					    "%u octets not zeros",
					    netaddrbuf, nbytes);
				result = ISC_R_FAILURE;
			}
		}
	}

	return (result);
}

static isc_result_t
parse_parameters(dns64_instance_t *inst, const char *parameters,
		 const void *cfg, const char *cfg_file, unsigned long cfg_line,
		 isc_mem_t *mctx, isc_log_t *lctx, dns_view_t *view,
		 void *actx)
{
	isc_result_t result = ISC_R_SUCCESS;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *param_obj = NULL;
	dns_acl_t *clients = NULL, *mapped = NULL, *excluded = NULL;
	const char *server = NULL, *contact = NULL;
	const cfg_obj_t *dns64_obj = NULL, *obj = NULL;
	const cfg_listelt_t *element = NULL;
	isc_buffer_t b;

	CHECK(cfg_parser_create(mctx, lctx, &parser));

	isc_buffer_constinit(&b, parameters, strlen(parameters));
	isc_buffer_add(&b, strlen(parameters));
	CHECK(cfg_parse_buffer(parser, &b, cfg_file, cfg_line,
			       &cfg_type_parameters, 0, &param_obj));

	CHECK(check_syntax(param_obj, (const cfg_obj_t *) cfg,
			   mctx, lctx, actx));

	CHECK(cfg_map_get(param_obj, "dns64", &dns64_obj));

	result = cfg_map_get(param_obj, "dns64-server", &obj);
	if (result == ISC_R_SUCCESS) {
		server = cfg_obj_asstring(obj);
	}

	obj = NULL;
	result = cfg_map_get(param_obj, "dns64-contact", &obj);
	if (result == ISC_R_SUCCESS) {
		contact = cfg_obj_asstring(obj);
	}

	for (element = cfg_list_first(dns64_obj);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		const cfg_obj_t *map = cfg_listelt_value(element);
		isc_netaddr_t na, suffix, *sp = NULL;
		unsigned int prefixlen;
		dns64_createflags_t dns64options = 0;
		dns64_t *dns64 = NULL;

		cfg_obj_asnetprefix(cfg_map_getname(map), &na,
				    &prefixlen);

		obj = NULL;
		(void)cfg_map_get(map, "suffix", &obj);
		if (obj != NULL) {
			sp = &suffix;
			isc_netaddr_fromsockaddr(sp,
					      cfg_obj_assockaddr(obj));
		}

		clients = mapped = excluded = NULL;

		obj = NULL;
		(void)cfg_map_get(map, "clients", &obj);
		if (obj != NULL) {
			CHECK(cfg_acl_fromconfig(obj,
					 (const cfg_obj_t *) cfg, lctx,
					 (cfg_aclconfctx_t *) actx,
					 mctx, 0, &clients));
		}

		obj = NULL;
		(void)cfg_map_get(map, "mapped", &obj);
		if (obj != NULL) {
			CHECK(cfg_acl_fromconfig(obj,
					 (const cfg_obj_t *) cfg, lctx,
					 (cfg_aclconfctx_t *) actx,
					 mctx, 0, &mapped));
		}
		obj = NULL;
		(void)cfg_map_get(map, "exclude", &obj);
		if (obj != NULL) {
			CHECK(cfg_acl_fromconfig(obj,
					 (const cfg_obj_t *) cfg, lctx,
					 (cfg_aclconfctx_t *) actx,
					 mctx, 0, &excluded));
		} else {
			if (inst->dns64_mapped == NULL) {
				CHECK(create_mapped_acl(mctx,
							&inst->dns64_mapped));
			}
			dns_acl_attach(inst->dns64_mapped, &excluded);
		}

		obj = NULL;
		(void)cfg_map_get(map, "recursive-only", &obj);
		if (obj != NULL && cfg_obj_asboolean(obj)) {
			dns64options |= RECURSIVE_ONLY;
		}

		obj = NULL;
		(void)cfg_map_get(map, "break-dnssec", &obj);
		if (obj != NULL && cfg_obj_asboolean(obj)) {
			dns64options |= BREAK_DNSSEC;
		}

		CHECK(dns64_createentry(mctx, &na, prefixlen, sp,
					clients, mapped, excluded,
					dns64options, &dns64));

		dns64_append(&inst->dns64list, dns64);
		inst->dns64cnt++;
		CHECK(dns64_reverse(view, lctx, &na, prefixlen,
				    server, contact));

		if (clients != NULL) {
			dns_acl_detach(&clients);
		}
		if (mapped != NULL) {
			dns_acl_detach(&mapped);
		}
		if (excluded != NULL) {
			dns_acl_detach(&excluded);
		}
	}


 cleanup:
	if (clients != NULL) {
		dns_acl_detach(&clients);
	}
	if (mapped != NULL) {
		dns_acl_detach(&mapped);
	}
	if (excluded != NULL) {
		dns_acl_detach(&excluded);
	}
	if (param_obj != NULL) {
		cfg_obj_destroy(parser, &param_obj);
	}
	if (parser != NULL) {
		cfg_parser_destroy(&parser);
	}
	return (result);
}

/**
 ** DNS64 SDB zone implementation starts here
 **/

typedef struct builtin {
	isc_result_t (*do_lookup)(dns_sdblookup_t *lookup);
	isc_mem_t *mctx;
	char *server;
	char *contact;
} builtin_t;

static isc_result_t dns64_zone_dolookup(dns_sdblookup_t *lookup);
static builtin_t dns64_builtin = { dns64_zone_dolookup, NULL, NULL, NULL };

/*
 * Pre computed HEX * 16 or 1 table.
 */
static const unsigned char hex16[256] = {
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*00*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,	/*10*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*20*/
	 0, 16, 32, 48, 64, 80, 96,112,128,144,  1,  1,  1,  1,  1,  1,	/*30*/
	 1,160,176,192,208,224,240,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*40*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*50*/
	 1,160,176,192,208,224,240,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*60*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*70*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*80*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*90*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*A0*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*B0*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*C0*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*D0*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1, /*E0*/
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1  /*F0*/
};

const unsigned char decimal[] = "0123456789";

static size_t
dns64_zone_rdata(unsigned char *v, size_t start, unsigned char *rdata) {
	size_t i, j = 0;

	for (i = 0; i < 4U; i++) {
		unsigned char c = v[start++];
		if (start == 7U) {
			start++;
		}
		if (c > 99) {
			rdata[j++] = 3;
			rdata[j++] = decimal[c / 100]; c = c % 100;
			rdata[j++] = decimal[c / 10]; c = c % 10;
			rdata[j++] = decimal[c];
		} else if (c > 9) {
			rdata[j++] = 2;
			rdata[j++] = decimal[c / 10]; c = c % 10;
			rdata[j++] = decimal[c];
		} else {
			rdata[j++] = 1;
			rdata[j++] = decimal[c];
		}
	}
	memmove(&rdata[j], "\07in-addr\04arpa", 14);
	return (j + 14);
}

static isc_result_t
dns64_zone_cname(const dns_name_t *zone,
	    const dns_name_t *name,
	    dns_sdblookup_t *lookup)
{
	size_t zlen, nlen, j, len;
	unsigned char v[16], n;
	unsigned int i;
	unsigned char rdata[sizeof("123.123.123.123.in-addr.arpa.")];
	unsigned char *ndata;

	/*
	 * The combined length of the zone and name is 74.
	 *
	 * The minimum zone length is 10 ((3)ip6(4)arpa(0)).
	 *
	 * The length of name should always be even as we are expecting
	 * a series of nibbles.
	 */
	zlen = zone->length;
	nlen = name->length;
	if ((zlen + nlen) > 74U || zlen < 10U || (nlen % 2) != 0U) {
		return (ISC_R_NOTFOUND);
	}

	/*
	 * We assume the zone name is well formed.
	 */

	/*
	 * XXXMPA We could check the dns64 suffix here if we need to.
	 */
	/*
	 * Check that name is a series of nibbles.
	 * Compute the byte values that correspond to the nibbles as we go.
	 *
	 * Shift the final result 4 bits, by setting 'i' to 1, if we if we
	 * have a odd number of nibbles so that "must be zero" tests below
	 * are byte aligned and we correctly return ISC_R_NOTFOUND or
	 * ISC_R_SUCCESS.  We will not generate a CNAME in this case.
	 */
	ndata = name->ndata;
	i = (nlen % 4) == 2U ? 1 : 0;
	j = nlen;
	memset(v, 0, sizeof(v));
	while (j != 0U) {
		INSIST((i / 2) < sizeof(v));
		if (ndata[0] != 1) {
			return (ISC_R_NOTFOUND);
		}
		n = hex16[ndata[1] & 0xff];
		if (n == 1) {
			return (ISC_R_NOTFOUND);
		}
		v[i / 2] = n | (v[i / 2] >> 4);
		j -= 2;
		ndata += 2;
		i++;
	}

	/*
	 * If we get here then we know name only consisted of nibbles.
	 * Now we need to determine if the name exists or not and whether
	 * it corresponds to a empty node in the zone or there should be
	 * a CNAME.
	 */
#define ZLEN(x) (10 + (x) / 2)
	switch (zlen) {
	case ZLEN(32):  /* prefix len 32 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 16U && v[(nlen - 1) / 4 - 4] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_zone_rdata(v, 8, rdata);
		break;
	case ZLEN(40):  /* prefix len 40 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 12U && v[(nlen - 1) / 4 - 3] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_zone_rdata(v, 6, rdata);
		break;
	case ZLEN(48):  /* prefix len 48 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 8U && v[(nlen - 1) / 4 - 2] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_zone_rdata(v, 5, rdata);
		break;
	case ZLEN(56):  /* prefix len 56 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (nlen > 4U && v[(nlen - 1) / 4 - 1] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_zone_rdata(v, 4, rdata);
		break;
	case ZLEN(64):  /* prefix len 64 */
		/*
		 * The nibbles that map to this byte must be zero for 'name'
		 * to exist in the zone.
		 */
		if (v[(nlen - 1) / 4] != 0) {
			return (ISC_R_NOTFOUND);
		}
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_zone_rdata(v, 3, rdata);
		break;
	case ZLEN(96):  /* prefix len 96 */
		/*
		 * If the total length is not 74 then this is a empty node
		 * so return success.
		 */
		if (nlen + zlen != 74U) {
			return (ISC_R_SUCCESS);
		}
		len = dns64_zone_rdata(v, 0, rdata);
		break;
	default:
		/*
		 * This should never be reached unless someone adds a
		 * zone declaration with this internal type to named.conf.
		 */
		return (ISC_R_NOTFOUND);
	}
	return (dns_sdb_putrdata(lookup, dns_rdatatype_cname, 600,
				 rdata, (unsigned int)len));
}

static isc_result_t
dns64_zone_lookup(const dns_name_t *zone, const dns_name_t *name,
	     void *dbdata, dns_sdblookup_t *lookup,
	     dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo)
{
	builtin_t *b = (builtin_t *) dbdata;

	UNUSED(methods);
	UNUSED(clientinfo);

	if (name->labels == 0 && name->length == 0) {
		return (b->do_lookup(lookup));
	} else {
		return (dns64_zone_cname(zone, name, lookup));
	}
}

static isc_result_t
dns64_zone_dolookup(dns_sdblookup_t *lookup) {
	UNUSED(lookup);
	return (ISC_R_SUCCESS);
}

static isc_result_t
dns64_zone_create(const char *zone, isc_mem_t *mctx, int argc, char **argv,
	     void *driverdata, void **dbdata)
{
	builtin_t *dns64;
	char *server;
	char *contact;

	UNUSED(zone);
	UNUSED(driverdata);

	if (argc != 3) {
		return (DNS_R_SYNTAX);
	}

	dns64 = isc_mem_get(mctx, sizeof(*dns64));
	server = isc_mem_strdup(mctx, argv[1]);
	contact = isc_mem_strdup(mctx, argv[2]);
	if (dns64 == NULL || server == NULL || contact == NULL) {
		*dbdata = &dns64_builtin;
		if (server != NULL) {
			isc_mem_free(mctx, server);
		}
		if (contact != NULL) {
			isc_mem_free(mctx, contact);
		}
		if (dns64 != NULL) {
			isc_mem_put(mctx, dns64, sizeof (*dns64));
		}
	} else {
		memmove(dns64, &dns64_builtin, sizeof (dns64_builtin));
		isc_mem_attach(mctx, &dns64->mctx);
		dns64->server = server;
		dns64->contact = contact;
		*dbdata = dns64;
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
dns64_zone_authority(const char *zone, void *dbdata, dns_sdblookup_t *lookup) {
	isc_result_t result;
	const char *contact = "hostmaster";
	const char *server = "@";
	builtin_t *b = (builtin_t *) dbdata;

	UNUSED(zone);
	UNUSED(dbdata);

	if (b->server != NULL) {
		server = b->server;
	}
	if (b->contact != NULL) {
		contact = b->contact;
	}

	result = dns_sdb_putsoa(lookup, server, contact, 0);
	if (result != ISC_R_SUCCESS) {
		return (ISC_R_FAILURE);
	}

	result = dns_sdb_putrr(lookup, "ns", 0, server);
	if (result != ISC_R_SUCCESS) {
		return (ISC_R_FAILURE);
	}

	return (ISC_R_SUCCESS);
}

static void
dns64_zone_destroy(const char *zone, void *driverdata, void **dbdata) {
	builtin_t *b = (builtin_t *) *dbdata;

	UNUSED(zone);
	UNUSED(driverdata);

	/*
	 * Don't free the static versions.
	 */
	if (*dbdata == &dns64_builtin) {
		return;
	}

	isc_mem_free(b->mctx, b->server);
	isc_mem_free(b->mctx, b->contact);
	isc_mem_putanddetach(&b->mctx, b, sizeof(*b));
}

static dns_sdbmethods_t dns64_methods = {
	NULL,
	dns64_zone_authority,
	NULL,           /* allnodes */
	dns64_zone_create,
	dns64_zone_destroy,
	dns64_zone_lookup,
};

/**
 ** Mandatory plugin API functions:
 **
 ** - plugin_check
 ** - plugin_destroy
 ** - plugin_register
 ** - plugin_version
 **/

/*
 * Called by ns_plugin_register() to register hook actions into
 * a hook table.
 */
isc_result_t
plugin_register(const char *parameters,
		const void *cfg, const char *cfg_file, unsigned long cfg_line,
		isc_mem_t *mctx, isc_log_t *lctx, void *actx,
		dns_view_t *view, void **instp)
{
	isc_result_t result;
	dns64_instance_t *inst = NULL;

	isc_log_write(lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "configuring 'dns64' "
		      "module from %s:%lu, %s parameters",
		      cfg_file, cfg_line,
		      parameters != NULL ? "with" : "no");

	inst = isc_mem_get(mctx, sizeof(*inst));
	memset(inst, 0, sizeof(*inst));
	isc_mem_attach(mctx, &inst->mctx);

	if (registrations++ == 0) {
		/*
		 * Set up dns64 SDB implementation.
		 */
		RUNTIME_CHECK(dns_sdb_register("_dns64", &dns64_methods, NULL,
					       DNS_SDBFLAG_RELATIVEOWNER |
					       DNS_SDBFLAG_RELATIVERDATA |
					       DNS_SDBFLAG_DNS64,
					       mctx, &dns64_impl)
			      == ISC_R_SUCCESS);
	}

	/*
	 * Parse parameters.
	 */
	if (parameters != NULL) {
		CHECK(parse_parameters(inst, parameters, cfg, cfg_file,
				       cfg_line, mctx, lctx, view, actx));
	}

	CHECK(isc_mempool_create(mctx, sizeof(dns64_data_t),
				 &inst->datapool));
	CHECK(isc_ht_init(&inst->ht, mctx, 16));

	/*
	 * Fill the mempool with 1K filter_aaaa state objects at
	 * a time; ideally after a single allocation, the mempool will
	 * have enough to handle all the simultaneous queries the system
	 * requires and it won't be necessary to allocate more.
	 *
	 * We don't set any limit on the number of free state objects
	 * so that they'll always be returned to the pool and not
	 * freed until the pool is destroyed on shutdown.
	 */
	isc_mempool_setfillcount(inst->datapool, 1024);
	isc_mempool_setfreemax(inst->datapool, UINT_MAX);

	/*
	 * Set hook points in the view's hooktable.
	 */
	install_hooks(view->hooktable, mctx, inst);

	*instp = inst;

 cleanup:
	return (result);
}

isc_result_t
plugin_check(const char *parameters,
	     const void *cfg, const char *cfg_file, unsigned long cfg_line,
	     isc_mem_t *mctx, isc_log_t *lctx, void *actx)
{
	UNUSED(parameters);
	UNUSED(cfg_file);
	UNUSED(cfg_line);
	UNUSED(cfg);
	UNUSED(mctx);
	UNUSED(lctx);
	UNUSED(actx);

	return (ISC_R_SUCCESS);
}

/*
 * Called by ns_plugins_free(); frees memory allocated by
 * the module when it was registered.
 */
void
plugin_destroy(void **instp) {
	dns64_instance_t *inst = (dns64_instance_t *) *instp;
	dns64_t *dns64 = NULL;

	if (inst->ht != NULL) {
		isc_ht_destroy(&inst->ht);
	}

	if (inst->datapool != NULL) {
		isc_mempool_destroy(&inst->datapool);
	}

	for (dns64 = ISC_LIST_HEAD(inst->dns64list);
	     dns64 != NULL;
	     dns64 = ISC_LIST_HEAD(inst->dns64list))
	{
		dns64_unlink(&inst->dns64list, dns64);
		dns64_destroyentry(&dns64);
	}

	if (inst->dns64_mapped != NULL) {
		dns_acl_detach(&inst->dns64_mapped);
	}

	isc_mem_putanddetach(&inst->mctx, inst, sizeof(*inst));
	*instp = NULL;

	/*
	 * We only unregister the SDB on the final dlclose()
	 */
	if (--registrations == 0) {
		dns_sdb_unregister(&dns64_impl);
	}

	return;
}

/*
 * Returns plugin API version for compatibility checks.
 */
int
plugin_version(void) {
	return (NS_PLUGIN_VERSION);
}


/*
 * Helper function to get persistent state information based on
 * the client address.
 */
static dns64_data_t *
client_state_get(const ns_client_t *client, dns64_instance_t *inst) {
	dns64_data_t *client_state = NULL;
	isc_result_t result;

	result = isc_ht_find(inst->ht, (const unsigned char *)&client,
			     sizeof(client), (void **)&client_state);

	return (result == ISC_R_SUCCESS ? client_state : NULL);
}

/*
 * Helper function to create persistent state information based on
 * the client address.
 */
static void
client_state_create(const ns_client_t *client, dns64_instance_t *inst) {
	dns64_data_t *client_state;
	isc_result_t result;

	client_state = isc_mempool_get(inst->datapool);
	if (client_state == NULL) {
		return;
	}

	client_state->aaaa = NULL;
	client_state->sigaaaa = NULL;
	client_state->aaaaok = NULL;
	client_state->aaaaoklen = 0;
	client_state->ttl = UINT32_MAX;
	client_state->flags = 0;
	client_state->dns64 = client_state->dns64_exclude = false;

	result = isc_ht_add(inst->ht, (const unsigned char *)&client,
			    sizeof(client), client_state);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

/*
 * Helper function to delete persistent state information based on
 * the client address.
 */
static void
client_state_destroy(const ns_client_t *client, dns64_instance_t *inst) {
	dns64_data_t *client_state = client_state_get(client, inst);
	isc_result_t result;

	if (client_state == NULL) {
		return;
	}

	result = isc_ht_delete(inst->ht, (const unsigned char *)&client,
			       sizeof(client));
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	isc_mempool_put(inst->datapool, client_state);
}

/**
 ** DNS64 data structure implementation starts here
 **/
static isc_result_t
dns64_createentry(isc_mem_t *mctx, const isc_netaddr_t *prefix,
		  unsigned int prefixlen, const isc_netaddr_t *suffix,
		  dns_acl_t *clients, dns_acl_t *mapped, dns_acl_t *excluded,
		  unsigned int flags, dns64_t **dns64p)
{
	dns64_t *dns64;
	unsigned int nbytes = 16;

	REQUIRE(prefix != NULL && prefix->family == AF_INET6);
	/* Legal prefix lengths from rfc6052.txt. */
	REQUIRE(prefixlen == 32 || prefixlen == 40 || prefixlen == 48 ||
		prefixlen == 56 || prefixlen == 64 || prefixlen == 96);
	REQUIRE(isc_netaddr_prefixok(prefix, prefixlen) == ISC_R_SUCCESS);
	REQUIRE(dns64p != NULL && *dns64p == NULL);

	if (suffix != NULL) {
		static const unsigned char zeros[16];
		REQUIRE(prefix->family == AF_INET6);
		nbytes = prefixlen / 8 + 4;
		/* Bits 64-71 are zeros. rfc6052.txt */
		if (prefixlen >= 32 && prefixlen <= 64) {
			nbytes++;
		}
		REQUIRE(memcmp(suffix->type.in6.s6_addr, zeros, nbytes) == 0);
	}

	dns64 = isc_mem_get(mctx, sizeof(dns64_t));
	if (dns64 == NULL) {
		return (ISC_R_NOMEMORY);
	}
	memset(dns64->bits, 0, sizeof(dns64->bits));
	memmove(dns64->bits, prefix->type.in6.s6_addr, prefixlen / 8);
	if (suffix != NULL) {
		memmove(dns64->bits + nbytes, suffix->type.in6.s6_addr + nbytes,
			16 - nbytes);
	}
	dns64->clients = NULL;
	if (clients != NULL) {
		dns_acl_attach(clients, &dns64->clients);
	}
	dns64->mapped = NULL;
	if (mapped != NULL) {
		dns_acl_attach(mapped, &dns64->mapped);
	}
	dns64->excluded = NULL;
	if (excluded != NULL) {
		dns_acl_attach(excluded, &dns64->excluded);
	}
	dns64->prefixlen = prefixlen;
	dns64->flags = flags;
	ISC_LINK_INIT(dns64, link);
	dns64->mctx = NULL;
	isc_mem_attach(mctx, &dns64->mctx);
	*dns64p = dns64;
	return (ISC_R_SUCCESS);
}

static void
dns64_destroyentry(dns64_t **dns64p) {
	dns64_t *dns64;

	REQUIRE(dns64p != NULL && *dns64p != NULL);

	dns64 = *dns64p;
	*dns64p = NULL;

	REQUIRE(!ISC_LINK_LINKED(dns64, link));

	if (dns64->clients != NULL) {
		dns_acl_detach(&dns64->clients);
	}
	if (dns64->mapped != NULL) {
		dns_acl_detach(&dns64->mapped);
	}
	if (dns64->excluded != NULL) {
		dns_acl_detach(&dns64->excluded);
	}
	isc_mem_putanddetach(&dns64->mctx, dns64, sizeof(*dns64));
}

static isc_result_t
dns64_aaaafroma(const dns64_t *dns64, const isc_netaddr_t *reqaddr,
		const dns_name_t *reqsigner, const dns_aclenv_t *env,
		unsigned int flags, unsigned char *a, unsigned char *aaaa)
{
	unsigned int nbytes, i;
	isc_result_t result;
	int match;

	if ((dns64->flags & RECURSIVE_ONLY) != 0 && (flags & RECURSIVE) == 0) {
		return (DNS_R_DISALLOWED);
	}

	if ((dns64->flags & BREAK_DNSSEC) == 0 && (flags & DNSSEC) != 0) {
		return (DNS_R_DISALLOWED);
	}

	if (dns64->clients != NULL) {
		result = dns_acl_match(reqaddr, reqsigner, dns64->clients,
				       env, &match, NULL);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		if (match <= 0) {
			return (DNS_R_DISALLOWED);
		}
	}

	if (dns64->mapped != NULL) {
		struct in_addr ina;
		isc_netaddr_t netaddr;

		memmove(&ina.s_addr, a, 4);
		isc_netaddr_fromin(&netaddr, &ina);
		result = dns_acl_match(&netaddr, NULL, dns64->mapped,
				       env, &match, NULL);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		if (match <= 0) {
			return (DNS_R_DISALLOWED);
		}
	}

	nbytes = dns64->prefixlen / 8;
	INSIST(nbytes <= 12);
	/* Copy prefix. */
	memmove(aaaa, dns64->bits, nbytes);
	/* Bits 64-71 are zeros. rfc6052.txt */
	if (nbytes == 8) {
		aaaa[nbytes++] = 0;
	}
	/* Copy mapped address. */
	for (i = 0; i < 4U; i++) {
		aaaa[nbytes++] = a[i];
		/* Bits 64-71 are zeros. rfc6052.txt */
		if (nbytes == 8) {
			aaaa[nbytes++] = 0;
		}
	}
	/* Copy suffix. */
	memmove(aaaa + nbytes, dns64->bits + nbytes, 16 - nbytes);
	return (ISC_R_SUCCESS);
}

static dns64_t *
dns64_next(dns64_t *dns64) {
	dns64 = ISC_LIST_NEXT(dns64, link);
	return (dns64);
}

static void
dns64_append(dns64list_t *list, dns64_t *dns64) {
	ISC_LIST_APPEND(*list, dns64, link);
}

static void
dns64_unlink(dns64list_t *list, dns64_t *dns64) {
	ISC_LIST_UNLINK(*list, dns64, link);
}

static bool
dns64_checkaaaa(const dns64_t *dns64, const isc_netaddr_t *reqaddr,
		const dns_name_t *reqsigner, const dns_aclenv_t *env,
		unsigned int flags, dns_rdataset_t *rdataset,
		bool *aaaaok, size_t aaaaoklen)
{
	struct in6_addr in6;
	isc_netaddr_t netaddr;
	isc_result_t result;
	int match;
	bool answer = false;
	bool found = false;
	unsigned int i, ok;

	REQUIRE(rdataset != NULL);
	REQUIRE(rdataset->type == dns_rdatatype_aaaa);
	REQUIRE(rdataset->rdclass == dns_rdataclass_in);
	if (aaaaok != NULL) {
		REQUIRE(aaaaoklen == dns_rdataset_count(rdataset));
	}

	for (; dns64 != NULL; dns64 = ISC_LIST_NEXT(dns64, link)) {
		if ((dns64->flags & RECURSIVE_ONLY) != 0 &&
		    (flags & RECURSIVE) == 0)
		{
			continue;
		}

		if ((dns64->flags & BREAK_DNSSEC) == 0 &&
		    (flags & DNSSEC) != 0)
		{
			continue;
		}

		/*
		 * Work out if this dns64 structure applies to this client.
		 */
		if (dns64->clients != NULL) {
			result = dns_acl_match(reqaddr, reqsigner,
					       dns64->clients, env,
					       &match, NULL);
			if (result != ISC_R_SUCCESS) {
				continue;
			}
			if (match <= 0) {
				continue;
			}
		}

		if (!found && aaaaok != NULL) {
			for (i = 0; i < aaaaoklen; i++) {
				aaaaok[i] = false;
			}
		}
		found = true;

		/*
		 * If we are not excluding any addresses then any AAAA
		 * will do.
		 */
		if (dns64->excluded == NULL) {
			answer = true;
			if (aaaaok == NULL) {
				goto done;
			}
			for (i = 0; i < aaaaoklen; i++) {
				aaaaok[i] = true;
			}
			goto done;
		}

		i = 0; ok = 0;
		for (result = dns_rdataset_first(rdataset);
		     result == ISC_R_SUCCESS;
		     result = dns_rdataset_next(rdataset)) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			if (aaaaok == NULL || !aaaaok[i]) {

				dns_rdataset_current(rdataset, &rdata);
				memmove(&in6.s6_addr, rdata.data, 16);
				isc_netaddr_fromin6(&netaddr, &in6);

				result = dns_acl_match(&netaddr, NULL,
						       dns64->excluded, env,
						       &match, NULL);
				if (result == ISC_R_SUCCESS && match <= 0) {
					answer = true;
					if (aaaaok == NULL) {
						goto done;
					}
					aaaaok[i] = true;
					ok++;
				}
			} else
				ok++;
			i++;
		}
		/*
		 * Are all addresses ok?
		 */
		if (aaaaok != NULL && ok == aaaaoklen) {
			goto done;
		}
	}

 done:
	if (!found && aaaaok != NULL) {
		for (i = 0; i < aaaaoklen; i++) {
			aaaaok[i] = true;
		}
	}
	return (found ? answer : true);
}

/**
 ** DNS64 query implementation begins here.
 **/
static uint32_t
dns64_ttl(dns_db_t *db, dns_dbversion_t *version) {
	dns_dbnode_t *node = NULL;
	dns_rdata_soa_t soa;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdataset_t rdataset;
	isc_result_t result;
	uint32_t ttl = UINT32_MAX;

	dns_rdataset_init(&rdataset);

	CHECK(dns_db_getoriginnode(db, &node));

	CHECK(dns_db_findrdataset(db, node, version, dns_rdatatype_soa,
				  0, 0, &rdataset, NULL));

	CHECK(dns_rdataset_first(&rdataset));

	dns_rdataset_current(&rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &soa, NULL);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	ttl = ISC_MIN(rdataset.ttl, soa.minimum);

cleanup:
	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}
	if (node != NULL) {
		dns_db_detachnode(db, &node);
	}
	return (ttl);
}

static bool
dns64_aaaaok(ns_client_t *client,
	     dns64_instance_t *inst, dns64_data_t *client_state,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	isc_netaddr_t netaddr;
	dns_aclenv_t *env = ns_interfacemgr_getaclenv(client->interface->mgr);
	dns64_t *dns64 = ISC_LIST_HEAD(inst->dns64list);
	unsigned int flags = 0;
	unsigned int i, count;
	bool *aaaaok;

	INSIST(client_state->aaaaok == NULL);
	INSIST(client_state->aaaaoklen == 0);
	INSIST(client_state->aaaa == NULL);
	INSIST(client_state->sigaaaa == NULL);

	if (dns64 == NULL) {
		return (true);
	}

	if (RECURSIONOK(client)) {
		flags |= RECURSIVE;
	}

	if (WANTDNSSEC(client) && sigrdataset != NULL &&
	    dns_rdataset_isassociated(sigrdataset))
		flags |= DNSSEC;

	count = dns_rdataset_count(rdataset);
	aaaaok = isc_mem_get(client->mctx, sizeof(bool) * count);

	isc_netaddr_fromsockaddr(&netaddr, &client->peeraddr);
	if (dns64_checkaaaa(dns64, &netaddr, client->signer,
			    env, flags, rdataset, aaaaok, count))
	{
		for (i = 0; i < count; i++) {
			if (aaaaok != NULL && !aaaaok[i]) {
				SAVE(client_state->aaaaok, aaaaok);
				client_state->aaaaoklen = count;
				break;
			}
		}
		if (aaaaok != NULL) {
			isc_mem_put(client->mctx, aaaaok,
				    sizeof(bool) * count);
		}
		return (true);
	}
	if (aaaaok != NULL) {
		isc_mem_put(client->mctx, aaaaok,
			    sizeof(bool) * count);
	}
	return (NS_HOOK_CONTINUE);
}

static isc_result_t
dns64_synth(query_ctx_t *qctx, dns64_instance_t *inst,
	    dns64_data_t *client_state)
{
	ns_client_t *client = qctx->client;
	dns_aclenv_t *env = ns_interfacemgr_getaclenv(client->interface->mgr);
	dns_name_t *name = qctx->fname, *mname = NULL;
	dns_rdata_t *dns64_rdata = NULL;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t *dns64_rdatalist = NULL;
	dns_rdataset_t *dns64_rdataset = NULL;
	dns_rdataset_t *mrdataset = NULL;
	isc_buffer_t *buffer = NULL;
	isc_region_t r;
	isc_result_t result;
	isc_netaddr_t netaddr;
	dns64_t *dns64 = NULL;
	unsigned int flags = 0;
	const dns_section_t section = DNS_SECTION_ANSWER;

	/*%
	 * To the current response for 'qctx->client', add the answer RRset
	 * '*rdatasetp' and an optional signature set '*sigrdatasetp', with
	 * owner name '*namep', to the answer section, unless they are
	 * already there.  Also add any pertinent additional data.
	 *
	 * If 'qctx->dbuf' is not NULL, then 'qctx->fname' is the name
	 * whose data is stored 'qctx->dbuf'.  In this case,
	 * query_addrrset() guarantees that when it returns the name
	 * will either have been kept or released.
	 */
	qctx->qtype = qctx->type = dns_rdatatype_aaaa;
	result = dns_message_findname(client->message, section,
				      name, dns_rdatatype_aaaa,
				      qctx->rdataset->covers,
				      &mname, &mrdataset);
	if (result == ISC_R_SUCCESS) {
		/*
		 * We've already got an RRset of the given name and type.
		 * There's nothing else to do;
		 */
		if (qctx->dbuf != NULL) {
			ns_client_releasename(client, &qctx->fname);
		}
		return (ISC_R_SUCCESS);
	} else if (result == DNS_R_NXDOMAIN) {
		/*
		 * The name doesn't exist.
		 */
		if (qctx->dbuf != NULL) {
			ns_client_keepname(client, name, qctx->dbuf);
		}
		dns_message_addname(client->message, name, section);
		qctx->fname = NULL;
		mname = name;
	} else {
		RUNTIME_CHECK(result == DNS_R_NXRRSET);
		if (qctx->dbuf != NULL) {
			ns_client_releasename(client, &qctx->fname);
		}
	}

	if (qctx->rdataset->trust != dns_trust_secure) {
		client->query.attributes &= ~NS_QUERYATTR_SECURE;
	}

	isc_netaddr_fromsockaddr(&netaddr, &client->peeraddr);

	CHECK(isc_buffer_allocate(client->mctx, &buffer,
				  inst->dns64cnt * 16 *
				  dns_rdataset_count(qctx->rdataset)));

	CHECK(dns_message_gettemprdataset(client->message, &dns64_rdataset));
	CHECK(dns_message_gettemprdatalist(client->message, &dns64_rdatalist));

	dns_rdatalist_init(dns64_rdatalist);
	dns64_rdatalist->rdclass = dns_rdataclass_in;
	dns64_rdatalist->type = dns_rdatatype_aaaa;
	if (client_state->ttl != UINT32_MAX) {
		dns64_rdatalist->ttl = ISC_MIN(qctx->rdataset->ttl,
					       client_state->ttl);
	} else {
		dns64_rdatalist->ttl = ISC_MIN(qctx->rdataset->ttl, 600);
	}

	if (RECURSIONOK(client)) {
		flags |= RECURSIVE;
	}

	/*
	 * We use the signatures from the A lookup to set the DNSSEC flag
	 * as this provides a easy way to see if the answer was signed.
	 */
	if (WANTDNSSEC(qctx->client) && qctx->sigrdataset != NULL &&
	    dns_rdataset_isassociated(qctx->sigrdataset))
	{
		flags |= DNSSEC;
	}

	for (result = dns_rdataset_first(qctx->rdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(qctx->rdataset)) {
		for (dns64 = ISC_LIST_HEAD(inst->dns64list);
		     dns64 != NULL; dns64 = dns64_next(dns64)) {

			dns_rdataset_current(qctx->rdataset, &rdata);
			isc_buffer_availableregion(buffer, &r);
			INSIST(r.length >= 16);
			result = dns64_aaaafroma(dns64, &netaddr,
						 client->signer, env, flags,
						 rdata.data, r.base);
			if (result != ISC_R_SUCCESS) {
				dns_rdata_reset(&rdata);
				continue;
			}
			isc_buffer_add(buffer, 16);
			isc_buffer_remainingregion(buffer, &r);
			isc_buffer_forward(buffer, 16);
			CHECK(dns_message_gettemprdata(client->message,
						       &dns64_rdata));

			dns_rdata_init(dns64_rdata);
			dns_rdata_fromregion(dns64_rdata, dns_rdataclass_in,
					     dns_rdatatype_aaaa, &r);
			ISC_LIST_APPEND(dns64_rdatalist->rdata, dns64_rdata,
					link);
			dns64_rdata = NULL;
			dns_rdata_reset(&rdata);
		}
	}
	if (result != ISC_R_NOMORE) {
		CHECK(result);
	}

	if (ISC_LIST_EMPTY(dns64_rdatalist->rdata)) {
		goto cleanup;
	}

	CHECK(dns_rdatalist_tordataset(dns64_rdatalist, dns64_rdataset));

	dns_rdataset_setownercase(dns64_rdataset, mname);
	client->query.attributes |= NS_QUERYATTR_NOADDITIONAL;
	dns64_rdataset->trust = qctx->rdataset->trust;

	/* Add rdataset to mname */
	ISC_LIST_APPEND(mname->list, dns64_rdataset, link);

	ns_query_setorder(client, mname, dns64_rdataset);

	dns64_rdataset = NULL;
	dns64_rdatalist = NULL;
	dns_message_takebuffer(client->message, &buffer);

	/*
	 * XXX this functionality will need to be restored:
	 * inc_stats(client, ns_statscounter_dns64);
	 */
	result = ISC_R_SUCCESS;

 cleanup:
	if (buffer != NULL) {
		isc_buffer_free(&buffer);
	}

	if (dns64_rdata != NULL) {
		dns_message_puttemprdata(client->message, &dns64_rdata);
	}

	if (dns64_rdataset != NULL) {
		dns_message_puttemprdataset(client->message, &dns64_rdataset);
	}

	if (dns64_rdatalist != NULL) {
		for (dns64_rdata = ISC_LIST_HEAD(dns64_rdatalist->rdata);
		     dns64_rdata != NULL;
		     dns64_rdata = ISC_LIST_HEAD(dns64_rdatalist->rdata))
		{
			ISC_LIST_UNLINK(dns64_rdatalist->rdata,
					dns64_rdata, link);
			dns_message_puttemprdata(client->message, &dns64_rdata);
		}
		dns_message_puttemprdatalist(client->message, &dns64_rdatalist);
	}

	return (result);
}

static void
dns64_filter(query_ctx_t *qctx, dns64_data_t *client_state) {
	ns_client_t *client = qctx->client;
	dns_name_t *name = qctx->fname, *mname = NULL;
	dns_rdata_t *myrdata = NULL;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t *myrdatalist = NULL;
	dns_rdataset_t *myrdataset = NULL;
	isc_buffer_t *buffer = NULL;
	isc_region_t r;
	isc_result_t result;
	unsigned int i;
	const dns_section_t section = DNS_SECTION_ANSWER;

	INSIST(client_state->aaaaok != NULL);
	INSIST(client_state->aaaaoklen ==
	       dns_rdataset_count(qctx->rdataset));

	result = dns_message_findname(client->message, section,
				      name, dns_rdatatype_aaaa,
				      qctx->rdataset->covers,
				      &mname, &myrdataset);
	if (result == ISC_R_SUCCESS) {
		/*
		 * We've already got an RRset of the given name and type.
		 * There's nothing else to do;
		 */
		if (qctx->dbuf != NULL) {
			ns_client_releasename(client, &qctx->fname);
		}
		return;
	} else if (result == DNS_R_NXDOMAIN) {
		mname = name;
		qctx->fname = NULL;
	} else {
		RUNTIME_CHECK(result == DNS_R_NXRRSET);
		if (qctx->dbuf != NULL) {
			ns_client_releasename(client, &qctx->fname);
		}
		qctx->dbuf = NULL;
	}

	if (qctx->rdataset->trust != dns_trust_secure) {
		client->query.attributes &= ~NS_QUERYATTR_SECURE;
	}

	CHECK(isc_buffer_allocate(client->mctx, &buffer,
				  16 * dns_rdataset_count(qctx->rdataset)));
	CHECK(dns_message_gettemprdataset(client->message, &myrdataset));
	CHECK(dns_message_gettemprdatalist(client->message, &myrdatalist));

	dns_rdatalist_init(myrdatalist);
	myrdatalist->rdclass = dns_rdataclass_in;
	myrdatalist->type = dns_rdatatype_aaaa;
	myrdatalist->ttl = qctx->rdataset->ttl;

	i = 0;
	for (result = dns_rdataset_first(qctx->rdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(qctx->rdataset))
	{
		if (!client_state->aaaaok[i++]) {
			continue;
		}
		dns_rdataset_current(qctx->rdataset, &rdata);
		INSIST(rdata.length == 16);
		isc_buffer_putmem(buffer, rdata.data, rdata.length);
		isc_buffer_remainingregion(buffer, &r);
		isc_buffer_forward(buffer, rdata.length);
		CHECK(dns_message_gettemprdata(client->message, &myrdata));
		dns_rdata_init(myrdata);
		dns_rdata_fromregion(myrdata, dns_rdataclass_in,
				     dns_rdatatype_aaaa, &r);
		ISC_LIST_APPEND(myrdatalist->rdata, myrdata, link);
		myrdata = NULL;
		dns_rdata_reset(&rdata);
	}
	if (result != ISC_R_NOMORE) {
		CHECK(result);
	}

	CHECK(dns_rdatalist_tordataset(myrdatalist, myrdataset));
	dns_rdataset_setownercase(myrdataset, name);
	client->query.attributes |= NS_QUERYATTR_NOADDITIONAL;
	if (mname == name) {
		if (qctx->dbuf != NULL) {
			ns_client_keepname(client, name, qctx->dbuf);
		}
		dns_message_addname(client->message, name,
				    section);
		qctx->dbuf = NULL;
	}
	myrdataset->trust = qctx->rdataset->trust;

	/* Add rdataset to mname */
	ISC_LIST_APPEND(mname->list, myrdataset, link);

	ns_query_setorder(client, mname, myrdataset);

	myrdataset = NULL;
	myrdatalist = NULL;
	dns_message_takebuffer(client->message, &buffer);

 cleanup:
	if (buffer != NULL) {
		isc_buffer_free(&buffer);
	}

	if (myrdata != NULL) {
		dns_message_puttemprdata(client->message, &myrdata);
	}

	if (myrdataset != NULL) {
		dns_message_puttemprdataset(client->message, &myrdataset);
	}

	if (myrdatalist != NULL) {
		for (myrdata = ISC_LIST_HEAD(myrdatalist->rdata);
		     myrdata != NULL;
		     myrdata = ISC_LIST_HEAD(myrdatalist->rdata))
		{
			ISC_LIST_UNLINK(myrdatalist->rdata, myrdata, link);
			dns_message_puttemprdata(client->message, &myrdata);
		}
		dns_message_puttemprdatalist(client->message, &myrdatalist);
	}
	if (qctx->dbuf != NULL) {
		ns_client_releasename(client, &name);
	}
}

static ns_hookresult_t
dns64_qctx_initialize(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	dns64_instance_t *inst = (dns64_instance_t *) cbdata;
	dns64_data_t *client_state;

	*resp = ISC_R_UNSET;

	client_state = client_state_get(qctx->client, inst);
	if (client_state == NULL) {
		client_state_create(qctx->client, inst);
	}

	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_respond_begin(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	dns64_instance_t *inst = (dns64_instance_t *) cbdata;
	dns64_data_t *client_state = client_state_get(qctx->client, inst);

	*resp = ISC_R_UNSET;

	if (client_state == NULL) {
		return (NS_HOOK_CONTINUE);
	}

	/*
	 * Check to see if the AAAA RRset has non-excluded addresses
	 * in it.  If not look for a A RRset.
	 */
	INSIST(client_state->aaaaok == NULL);

	if (qctx->qtype == dns_rdatatype_aaaa &&
	    !client_state->dns64_exclude &&
	    !ISC_LIST_EMPTY(inst->dns64list) &&
	    qctx->client->message->rdclass == dns_rdataclass_in &&
	    !dns64_aaaaok(qctx->client, inst, client_state,
			  qctx->rdataset, qctx->sigrdataset))
	{
		/*
		 * If any previously-configured module has set up recursion
		 * before we call ns_query_lookup(), we might assert. Just
		 * return without doing anything in that case.
		 */
		if ((qctx->client->query.attributes &
		     NS_QUERYATTR_RECURSING) != 0)
		{
			return (false);
		}

		/*
		 * Look to see if there are A records for this name.
		 */
		client_state->ttl = qctx->rdataset->ttl;
		SAVE(client_state->aaaa, qctx->rdataset);
		SAVE(client_state->sigaaaa, qctx->sigrdataset);
		ns_client_releasename(qctx->client, &qctx->fname);
		dns_db_detachnode(qctx->db, &qctx->node);
		qctx->type = qctx->qtype = dns_rdatatype_a;
		client_state->dns64_exclude = client_state->dns64 = true;

		*resp = ns_query_lookup(qctx);
		return (NS_HOOK_RETURN);
	}

	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_addanswer(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	dns64_instance_t *inst = (dns64_instance_t *) cbdata;
	dns64_data_t *client_state = client_state_get(qctx->client, inst);

	*resp = ISC_R_UNSET;

	if (client_state == NULL) {
		return (NS_HOOK_CONTINUE);
	}

	if (client_state->dns64) {
		isc_result_t result = dns64_synth(qctx, inst, client_state);
		qctx->noqname = NULL;
		dns_rdataset_disassociate(qctx->rdataset);
		dns_message_puttemprdataset(qctx->client->message,
					    &qctx->rdataset);
		if (result == ISC_R_NOMORE) {
			if (client_state->dns64_exclude) {
				if (!qctx->is_zone) {
					*resp = ns_query_done(qctx);
					return (NS_HOOK_RETURN);
				}
				/*
				 * Add a fake SOA record.
				 */
				(void) ns_query_addsoa(qctx, 600,
						       DNS_SECTION_AUTHORITY);
				*resp = ns_query_done(qctx);
				return (NS_HOOK_RETURN);
			}
			if (qctx->is_zone) {
				qctx->nxresult = DNS_R_NXDOMAIN;
				*resp = ns_query_nodata(qctx);
			} else {
				qctx->nxresult = DNS_R_NXDOMAIN;
				*resp = ns_query_ncache(qctx);
			}
		} else if (result != ISC_R_SUCCESS) {
			qctx->result = result;
			*resp = ns_query_done(qctx);
		} else {
			*resp = ISC_R_COMPLETE;
		}
		return (NS_HOOK_RETURN);
	} else if (client_state->aaaaok != NULL) {
		dns64_filter(qctx, client_state);
		ns_client_putrdataset(qctx->client, &qctx->rdataset);
		*resp = ISC_R_COMPLETE;
		return (NS_HOOK_RETURN);
	}

	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_delegation_recurse(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	dns64_instance_t *inst = (dns64_instance_t *) cbdata;
	dns64_data_t *client_state = client_state_get(qctx->client, inst);

	*resp = ISC_R_UNSET;

	if (client_state == NULL) {
		return (NS_HOOK_CONTINUE);
	}

	/*
	 * Look up an A record so we can synthesize DNS64.
	 */
	if (client_state->dns64) {
		qctx->result = ns_query_recurse(qctx->client,
						dns_rdatatype_a,
						qctx->client->query.qname,
						NULL, NULL,
						qctx->resuming);
		qctx->client->query.attributes |= NS_QUERYATTR_RECURSING;
		*resp = ISC_R_COMPLETE;
		return (NS_HOOK_RETURN);
	}

	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_nodata_begin(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	dns64_instance_t *inst = (dns64_instance_t *) cbdata;
	dns64_data_t *client_state = client_state_get(qctx->client, inst);
	isc_result_t result;

	*resp = ISC_R_UNSET;

	if (client_state == NULL) {
		return (NS_HOOK_CONTINUE);
	}

	if (client_state->dns64 && !client_state->dns64_exclude) {
		isc_buffer_t b;

		/*
		 * Restore the answers from the previous AAAA lookup.
		 */
		if (qctx->rdataset != NULL) {
			ns_client_putrdataset(qctx->client, &qctx->rdataset);
		}
		if (qctx->sigrdataset != NULL) {
			ns_client_putrdataset(qctx->client, &qctx->sigrdataset);
		}
		RESTORE(qctx->rdataset, client_state->aaaa);
		RESTORE(qctx->sigrdataset, client_state->sigaaaa);
		if (qctx->fname == NULL) {
			qctx->dbuf = ns_client_getnamebuf(qctx->client);
			if (qctx->dbuf == NULL) {
				QUERY_ERROR(qctx, DNS_R_SERVFAIL);
				*resp = ns_query_done(qctx);
				return (NS_HOOK_RETURN);
			}
			qctx->fname = ns_client_newname(qctx->client,
						    qctx->dbuf, &b);
			if (qctx->fname == NULL) {
				QUERY_ERROR(qctx, DNS_R_SERVFAIL);
				*resp = ns_query_done(qctx);
				return (NS_HOOK_RETURN);
			}
		}
		dns_name_copy(qctx->client->query.qname, qctx->fname, NULL);
		client_state->dns64 = false;
	} else if ((qctx->nxresult == DNS_R_NXRRSET ||
		    qctx->nxresult == DNS_R_NCACHENXRRSET) &&
		   !ISC_LIST_EMPTY(inst->dns64list) &&
		   qctx->client->message->rdclass == dns_rdataclass_in &&
		   qctx->qtype == dns_rdatatype_aaaa)
	{
		/*
		 * Look to see if there are A records for this name.
		 */
		switch (qctx->nxresult) {
		case DNS_R_NCACHENXRRSET:
			/*
			 * This is from the negative cache; if the ttl is
			 * zero, we need to work out whether we have just
			 * decremented to zero or there was no negative
			 * cache ttl in the answer.
			 */
			if (qctx->rdataset->ttl != 0) {
				client_state->ttl = qctx->rdataset->ttl;
				break;
			}
			result = dns_rdataset_first(qctx->rdataset);
			if (result == ISC_R_SUCCESS) {
				client_state->ttl = 0;
			}
			break;
		case DNS_R_NXRRSET:
			client_state->ttl = dns64_ttl(qctx->db, qctx->version);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}

		SAVE(client_state->aaaa, qctx->rdataset);
		SAVE(client_state->sigaaaa, qctx->sigrdataset);
		ns_client_releasename(qctx->client, &qctx->fname);
		dns_db_detachnode(qctx->db, &qctx->node);
		qctx->type = qctx->qtype = dns_rdatatype_a;
		client_state->dns64 = true;
		*resp = ns_query_lookup(qctx);
		return (NS_HOOK_RETURN);
	}

	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_qctx_destroy(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	dns64_instance_t *inst = (dns64_instance_t *) cbdata;
	dns64_data_t *client_state = client_state_get(qctx->client, inst);

	*resp = ISC_R_UNSET;

	if (!qctx->detach_client) {
		return (NS_HOOK_CONTINUE);
	}

	if (client_state->aaaa != NULL) {
		ns_client_putrdataset(qctx->client, &client_state->aaaa);
	}
	if (client_state->sigaaaa != NULL) {
		ns_client_putrdataset(qctx->client, &client_state->sigaaaa);
	}
	if (client_state->aaaaok != NULL) {
		isc_mem_put(qctx->client->mctx, client_state->aaaaok,
			    client_state->aaaaoklen * sizeof(bool));
		client_state->aaaaok =  NULL;
		client_state->aaaaoklen =  0;
	}

	client_state_destroy(qctx->client, inst);

	return (NS_HOOK_CONTINUE);
}
