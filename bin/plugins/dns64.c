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
#include <isc/list.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <ns/client.h>
#include <ns/hooks.h>
#include <ns/interfacemgr.h>
#include <ns/log.h>
#include <ns/query.h>
#include <ns/types.h>

#include <dns/db.h>
#include <dns/dns64.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/rdatalist.h>
#include <dns/result.h>
#include <dns/types.h>
#include <dns/view.h>

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

/*
 * Client attribute tests.
 */
/*% Recursion OK? */
#define RECURSIONOK(c)		(((c)->query.attributes & \
				  NS_QUERYATTR_RECURSIONOK) != 0)
/*% Want DNSSEC? */
#define WANTDNSSEC(c)		(((c)->attributes & \
				  NS_CLIENTATTR_WANTDNSSEC) != 0)

#define DNS64(c)		(((c)->query.attributes & \
				  NS_QUERYATTR_DNS64) != 0)

#define DNS64EXCLUDE(c)		(((c)->query.attributes & \
				  NS_QUERYATTR_DNS64EXCLUDE) != 0)

static uint32_t
dns64_ttl(dns_db_t *db, dns_dbversion_t *version);

static bool
dns64_aaaaok(ns_client_t *client, dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset);

static isc_result_t
dns64_synth(query_ctx_t *qctx);

static void
dns64_filter(query_ctx_t *qctx);

/*
 * Hook registration structures: pointers to these structures will
 * be added to a hook table when this module is registered.
 */
static ns_hookresult_t
dns64_qctx_initialize(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_init = {
	.action = dns64_qctx_initialize,
};

static ns_hookresult_t
dns64_respond_begin(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_respbegin = {
	.action = dns64_respond_begin,
};

static ns_hookresult_t
dns64_addanswer(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_addanswerbegin = {
	.action = dns64_addanswer,
};

static ns_hookresult_t
dns64_resume_restored(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_resumerest = {
	.action = dns64_resume_restored,
};

static ns_hookresult_t
dns64_notfound_recurse(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_nfrec = {
	.action = dns64_notfound_recurse,
};

static ns_hookresult_t
dns64_delegation_recurse(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_delrec = {
	.action = dns64_delegation_recurse,
};

static ns_hookresult_t
dns64_nodata_begin(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_nodata = {
	.action = dns64_nodata_begin,
};

static ns_hookresult_t
dns64_zerottl_recurse(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_zerottl = {
	.action = dns64_zerottl_recurse,
};

static ns_hookresult_t
dns64_qctx_destroy(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t dns64_destroy = {
	.action = dns64_qctx_destroy,
};

/**
 ** Support for parsing of parameters and configuration of the module.
 **/

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
		ns_hooktable_t *hooktable, void **instp)
{

	UNUSED(cfg);
	UNUSED(actx);
	UNUSED(instp);

	isc_log_write(lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "loading 'dns64' "
		      "module from %s:%lu, %s parameters",
		      cfg_file, cfg_line, parameters != NULL ? "with" : "no");

	ns_hook_add(hooktable, mctx,
		    NS_QUERY_QCTX_INITIALIZED, &dns64_init);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_RESPOND_BEGIN, &dns64_respbegin);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_ADDANSWER_BEGIN, &dns64_addanswerbegin);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_RESUME_RESTORED, &dns64_resumerest);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_NOTFOUND_RECURSE, &dns64_nfrec);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_DELEGATION_RECURSE_BEGIN, &dns64_delrec);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_NODATA_BEGIN, &dns64_nodata);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_ZEROTTL_RECURSE, &dns64_zerottl);
	ns_hook_add(hooktable, mctx,
		    NS_QUERY_QCTX_DESTROYED, &dns64_destroy);

	return (ISC_R_SUCCESS);
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
	UNUSED(instp);

	return;

}

/*
 * Returns plugin API version for compatibility checks.
 */
int
plugin_version(void) {
	return (NS_PLUGIN_VERSION);
}

/**
 ** DNS64 feature implementation begins here.
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

	result = dns_db_getoriginnode(db, &node);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_db_findrdataset(db, node, version, dns_rdatatype_soa,
				     0, 0, &rdataset, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_rdataset_first(&rdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	dns_rdataset_current(&rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &soa, NULL);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	ttl = ISC_MIN(rdataset.ttl, soa.minimum);

cleanup:
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (node != NULL)
		dns_db_detachnode(db, &node);
	return (ttl);
}

static bool
dns64_aaaaok(ns_client_t *client, dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset)
{
	isc_netaddr_t netaddr;
	dns_aclenv_t *env = ns_interfacemgr_getaclenv(client->interface->mgr);
	dns_dns64_t *dns64 = ISC_LIST_HEAD(client->view->dns64);
	unsigned int flags = 0;
	unsigned int i, count;
	bool *aaaaok;

	INSIST(client->dns64_aaaaok == NULL);
	INSIST(client->dns64_aaaaoklen == 0);
	INSIST(client->dns64_aaaa == NULL);
	INSIST(client->dns64_sigaaaa == NULL);

	if (dns64 == NULL)
		return (true);

	if (RECURSIONOK(client))
		flags |= DNS_DNS64_RECURSIVE;

	if (WANTDNSSEC(client) && sigrdataset != NULL &&
	    dns_rdataset_isassociated(sigrdataset))
		flags |= DNS_DNS64_DNSSEC;

	count = dns_rdataset_count(rdataset);
	aaaaok = isc_mem_get(client->mctx, sizeof(bool) * count);

	isc_netaddr_fromsockaddr(&netaddr, &client->peeraddr);
	if (dns_dns64_aaaaok(dns64, &netaddr, client->signer,
			     env, flags, rdataset, aaaaok, count))
	{
		for (i = 0; i < count; i++) {
			if (aaaaok != NULL && !aaaaok[i]) {
				SAVE(client->dns64_aaaaok, aaaaok);
				client->dns64_aaaaoklen = count;
				break;
			}
		}
		if (aaaaok != NULL)
			isc_mem_put(client->mctx, aaaaok,
				    sizeof(bool) * count);
		return (true);
	}
	if (aaaaok != NULL)
		isc_mem_put(client->mctx, aaaaok,
			    sizeof(bool) * count);
	return (NS_HOOK_CONTINUE);
}

static isc_result_t
dns64_synth(query_ctx_t *qctx) {
	ns_client_t *client = qctx->client;
	dns_aclenv_t *env = ns_interfacemgr_getaclenv(client->interface->mgr);
	dns_name_t *name, *mname;
	dns_rdata_t *dns64_rdata;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t *dns64_rdatalist;
	dns_rdataset_t *dns64_rdataset;
	dns_rdataset_t *mrdataset;
	isc_buffer_t *buffer;
	isc_region_t r;
	isc_result_t result;
	dns_view_t *view = client->view;
	isc_netaddr_t netaddr;
	dns_dns64_t *dns64;
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

	name = qctx->fname;
	mname = NULL;
	mrdataset = NULL;
	buffer = NULL;
	dns64_rdata = NULL;
	dns64_rdataset = NULL;
	dns64_rdatalist = NULL;
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

	result = isc_buffer_allocate(client->mctx, &buffer,
				     view->dns64cnt * 16 *
				     dns_rdataset_count(qctx->rdataset));
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_gettemprdataset(client->message,
					     &dns64_rdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_gettemprdatalist(client->message,
					      &dns64_rdatalist);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	dns_rdatalist_init(dns64_rdatalist);
	dns64_rdatalist->rdclass = dns_rdataclass_in;
	dns64_rdatalist->type = dns_rdatatype_aaaa;
	if (client->dns64_ttl != UINT32_MAX)
		dns64_rdatalist->ttl = ISC_MIN(qctx->rdataset->ttl,
					       client->dns64_ttl);
	else
		dns64_rdatalist->ttl = ISC_MIN(qctx->rdataset->ttl, 600);

	if (RECURSIONOK(client))
		flags |= DNS_DNS64_RECURSIVE;

	/*
	 * We use the signatures from the A lookup to set DNS_DNS64_DNSSEC
	 * as this provides a easy way to see if the answer was signed.
	 */
	if (WANTDNSSEC(qctx->client) && qctx->sigrdataset != NULL &&
	    dns_rdataset_isassociated(qctx->sigrdataset))
		flags |= DNS_DNS64_DNSSEC;

	for (result = dns_rdataset_first(qctx->rdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(qctx->rdataset)) {
		for (dns64 = ISC_LIST_HEAD(client->view->dns64);
		     dns64 != NULL; dns64 = dns_dns64_next(dns64)) {

			dns_rdataset_current(qctx->rdataset, &rdata);
			isc_buffer_availableregion(buffer, &r);
			INSIST(r.length >= 16);
			result = dns_dns64_aaaafroma(dns64, &netaddr,
						     client->signer, env, flags,
						     rdata.data, r.base);
			if (result != ISC_R_SUCCESS) {
				dns_rdata_reset(&rdata);
				continue;
			}
			isc_buffer_add(buffer, 16);
			isc_buffer_remainingregion(buffer, &r);
			isc_buffer_forward(buffer, 16);
			result = dns_message_gettemprdata(client->message,
							  &dns64_rdata);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			dns_rdata_init(dns64_rdata);
			dns_rdata_fromregion(dns64_rdata, dns_rdataclass_in,
					     dns_rdatatype_aaaa, &r);
			ISC_LIST_APPEND(dns64_rdatalist->rdata, dns64_rdata,
					link);
			dns64_rdata = NULL;
			dns_rdata_reset(&rdata);
		}
	}
	if (result != ISC_R_NOMORE)
		goto cleanup;

	if (ISC_LIST_EMPTY(dns64_rdatalist->rdata))
		goto cleanup;

	result = dns_rdatalist_tordataset(dns64_rdatalist, dns64_rdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
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
	 * XXX: this functionality will need to be restored
	 * inc_stats(client, ns_statscounter_dns64);
	 */
	result = ISC_R_SUCCESS;

 cleanup:
	if (buffer != NULL)
		isc_buffer_free(&buffer);

	if (dns64_rdata != NULL)
		dns_message_puttemprdata(client->message, &dns64_rdata);

	if (dns64_rdataset != NULL)
		dns_message_puttemprdataset(client->message, &dns64_rdataset);

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
dns64_filter(query_ctx_t *qctx) {
	ns_client_t *client = qctx->client;
	dns_name_t *name, *mname;
	dns_rdata_t *myrdata;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t *myrdatalist;
	dns_rdataset_t *myrdataset;
	isc_buffer_t *buffer;
	isc_region_t r;
	isc_result_t result;
	unsigned int i;
	const dns_section_t section = DNS_SECTION_ANSWER;

	INSIST(client->dns64_aaaaok != NULL);
	INSIST(client->dns64_aaaaoklen ==
	       dns_rdataset_count(qctx->rdataset));

	name = qctx->fname;
	mname = NULL;
	buffer = NULL;
	myrdata = NULL;
	myrdataset = NULL;
	myrdatalist = NULL;
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

	result = isc_buffer_allocate(client->mctx, &buffer,
				     16 * dns_rdataset_count(qctx->rdataset));
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_gettemprdataset(client->message, &myrdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_message_gettemprdatalist(client->message, &myrdatalist);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	dns_rdatalist_init(myrdatalist);
	myrdatalist->rdclass = dns_rdataclass_in;
	myrdatalist->type = dns_rdatatype_aaaa;
	myrdatalist->ttl = qctx->rdataset->ttl;

	i = 0;
	for (result = dns_rdataset_first(qctx->rdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(qctx->rdataset))
	{
		if (!client->dns64_aaaaok[i++])
			continue;
		dns_rdataset_current(qctx->rdataset, &rdata);
		INSIST(rdata.length == 16);
		isc_buffer_putmem(buffer, rdata.data, rdata.length);
		isc_buffer_remainingregion(buffer, &r);
		isc_buffer_forward(buffer, rdata.length);
		result = dns_message_gettemprdata(client->message, &myrdata);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		dns_rdata_init(myrdata);
		dns_rdata_fromregion(myrdata, dns_rdataclass_in,
				     dns_rdatatype_aaaa, &r);
		ISC_LIST_APPEND(myrdatalist->rdata, myrdata, link);
		myrdata = NULL;
		dns_rdata_reset(&rdata);
	}
	if (result != ISC_R_NOMORE)
		goto cleanup;

	result = dns_rdatalist_tordataset(myrdatalist, myrdataset);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
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
	if (buffer != NULL)
		isc_buffer_free(&buffer);

	if (myrdata != NULL)
		dns_message_puttemprdata(client->message, &myrdata);

	if (myrdataset != NULL)
		dns_message_puttemprdataset(client->message, &myrdataset);

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
	UNUSED(arg);
	UNUSED(cbdata);

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_respond_begin(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;

	UNUSED(cbdata);

	/*
	 * Check to see if the AAAA RRset has non-excluded addresses
	 * in it.  If not look for a A RRset.
	 */
	INSIST(qctx->client->dns64_aaaaok == NULL);

	if (qctx->qtype == dns_rdatatype_aaaa && !qctx->dns64_exclude &&
	    !ISC_LIST_EMPTY(qctx->view->dns64) &&
	    qctx->client->message->rdclass == dns_rdataclass_in &&
	    !dns64_aaaaok(qctx->client, qctx->rdataset, qctx->sigrdataset))
	{
		/*
		 * Look to see if there are A records for this name.
		 */
		qctx->client->dns64_ttl = qctx->rdataset->ttl;
		SAVE(qctx->client->dns64_aaaa, qctx->rdataset);
		SAVE(qctx->client->dns64_sigaaaa, qctx->sigrdataset);
		ns_client_releasename(qctx->client, &qctx->fname);
		dns_db_detachnode(qctx->db, &qctx->node);
		qctx->type = qctx->qtype = dns_rdatatype_a;
		qctx->dns64_exclude = qctx->dns64 = true;

		/*
		 * XXX: we are depending here on DNS64
		 * being reached before any other modules that
		 * might set up recursion. In particular if
		 * the filter-aaaa module runs first, there'll
		 * be an assertion failure. We need to make this
		 * order-indeendent.
		 */
		*resp = ns_query_lookup(qctx);
		return (NS_HOOK_RETURN);
	}

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_addanswer(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;

	UNUSED(cbdata);

	if (qctx->dns64) {
		isc_result_t result = dns64_synth(qctx);
		qctx->noqname = NULL;
		dns_rdataset_disassociate(qctx->rdataset);
		dns_message_puttemprdataset(qctx->client->message,
					    &qctx->rdataset);
		if (result == ISC_R_NOMORE) {
			if (qctx->dns64_exclude) {
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
	} else if (qctx->client->dns64_aaaaok != NULL) {
		dns64_filter(qctx);
		ns_client_putrdataset(qctx->client, &qctx->rdataset);
		*resp = ISC_R_COMPLETE;
		return (NS_HOOK_RETURN);
	}

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_resume_restored(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;

	UNUSED(cbdata);

	if (DNS64(qctx->client)) {
		qctx->client->query.attributes &= ~NS_QUERYATTR_DNS64;
		qctx->dns64 = true;
	}

	if (DNS64EXCLUDE(qctx->client)) {
		qctx->client->query.attributes &= ~NS_QUERYATTR_DNS64EXCLUDE;
		qctx->dns64_exclude = true;
	}

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_notfound_recurse(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;

	UNUSED(cbdata);

	if (qctx->dns64) {
		qctx->client->query.attributes |= NS_QUERYATTR_DNS64;
	}
	if (qctx->dns64_exclude) {
		qctx->client->query.attributes |= NS_QUERYATTR_DNS64EXCLUDE;
	}

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_delegation_recurse(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;

	UNUSED(cbdata);

	/*
	 * Look up an A record so we can synthesize DNS64.
	 */
	if (qctx->dns64) {
		qctx->result = ns_query_recurse(qctx->client,
						dns_rdatatype_a,
						qctx->client->query.qname,
						NULL, NULL,
						qctx->resuming);
		qctx->client->query.attributes |= NS_QUERYATTR_RECURSING;
		if (qctx->result == ISC_R_SUCCESS) {
			qctx->client->query.attributes |= NS_QUERYATTR_DNS64;
			if (qctx->dns64_exclude) {
				qctx->client->query.attributes |=
				      NS_QUERYATTR_DNS64EXCLUDE;
			}
		}
		*resp = ISC_R_COMPLETE;
		return (NS_HOOK_RETURN);
	}

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_nodata_begin(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;

	UNUSED(cbdata);

	if (qctx->dns64 && !qctx->dns64_exclude) {
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
		RESTORE(qctx->rdataset, qctx->client->dns64_aaaa);
		RESTORE(qctx->sigrdataset, qctx->client->dns64_sigaaaa);
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
		qctx->dns64 = false;
	} else if ((qctx->nxresult == DNS_R_NXRRSET ||
		    qctx->nxresult == DNS_R_NCACHENXRRSET) &&
		   !ISC_LIST_EMPTY(qctx->view->dns64) &&
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
				qctx->client->dns64_ttl = qctx->rdataset->ttl;
				break;
			}
			if (dns_rdataset_first(qctx->rdataset) == ISC_R_SUCCESS)
				qctx->client->dns64_ttl = 0;
			break;
		case DNS_R_NXRRSET:
			qctx->client->dns64_ttl =
				dns64_ttl(qctx->db, qctx->version);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}

		SAVE(qctx->client->dns64_aaaa, qctx->rdataset);
		SAVE(qctx->client->dns64_sigaaaa, qctx->sigrdataset);
		ns_client_releasename(qctx->client, &qctx->fname);
		dns_db_detachnode(qctx->db, &qctx->node);
		qctx->type = qctx->qtype = dns_rdatatype_a;
		qctx->dns64 = true;
		*resp = ns_query_lookup(qctx);
		return (NS_HOOK_RETURN);
	}

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_zerottl_recurse(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;

	UNUSED(cbdata);

	if (qctx->dns64) {
		qctx->client->query.attributes |= NS_QUERYATTR_DNS64;
	}
	if (qctx->dns64_exclude) {
		qctx->client->query.attributes |= NS_QUERYATTR_DNS64EXCLUDE;
	}

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}

static ns_hookresult_t
dns64_qctx_destroy(void *arg, void *cbdata, isc_result_t *resp) {
	UNUSED(arg);
	UNUSED(cbdata);

	*resp = ISC_R_UNSET;
	return (NS_HOOK_CONTINUE);
}
