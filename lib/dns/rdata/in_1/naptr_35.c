/*
 * Copyright (C) 1999 Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

 /* $Id: naptr_35.c,v 1.9 1999/08/02 22:18:01 halley Exp $ */

 /* RFC 2168 */

#ifndef RDATA_IN_1_NAPTR_35_C
#define RDATA_IN_1_NAPTR_35_C

static dns_result_t
fromtext_in_naptr(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_lex_t *lexer, dns_name_t *origin,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;

	REQUIRE(type == 35);
	REQUIRE(rdclass == 1);

	/* priority */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* weight */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* flags */
	RETERR(gettoken(lexer, &token, isc_tokentype_qstring, ISC_FALSE));
	RETERR(txt_fromtext(&token.value.as_textregion, target));

	/* service */
	RETERR(gettoken(lexer, &token, isc_tokentype_qstring, ISC_FALSE));
	RETERR(txt_fromtext(&token.value.as_textregion, target));

	/* regexp */
	RETERR(gettoken(lexer, &token, isc_tokentype_qstring, ISC_FALSE));
	RETERR(txt_fromtext(&token.value.as_textregion, target));

	/* replacement */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region,
			  ISC_BUFFERTYPE_TEXT);
	origin = (origin != NULL) ? origin : dns_rootname;
	return (dns_name_fromtext(&name, &buffer, origin, downcase, target));
}

static dns_result_t
totext_in_naptr(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, 
		isc_buffer_t *target) 
{
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;
	char buf[sizeof "64000"];
	unsigned short num;

	REQUIRE(rdata->type == 35);
	REQUIRE(rdata->rdclass == 1);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	/* priority */
	dns_rdata_toregion(rdata, &region);
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	sprintf(buf, "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* weight */
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	sprintf(buf, "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/* flags */
	RETERR(txt_totext(&region, target));
	RETERR(str_totext(" ", target));

	/* service */
	RETERR(txt_totext(&region, target));
	RETERR(str_totext(" ", target));

	/* regexp */
	RETERR(txt_totext(&region, target));
	RETERR(str_totext(" ", target));

	/* replacement */
	dns_name_fromregion(&name, &region);
	sub = name_prefix(&name, tctx->origin, &prefix);
	return(dns_name_totext(&prefix, sub, target));
}

static dns_result_t
fromwire_in_naptr(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		  isc_buffer_t *source, dns_decompress_t *dctx,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
        dns_name_t name;
	isc_region_t sr;

	REQUIRE(type == 35);
	REQUIRE(rdclass == 1);

	if (dns_decompress_edns(dctx) >= 1 || !dns_decompress_strict(dctx))
		dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
	else
		dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);
        
        dns_name_init(&name, NULL);

	/* priority, weight */
	isc_buffer_active(source, &sr);
	if (sr.length < 4)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 4));
	isc_buffer_forward(source, 4);

	/* flags */
	RETERR(txt_fromwire(source, target));

	/* service */
	RETERR(txt_fromwire(source, target));

	/* regexp */
	RETERR(txt_fromwire(source, target));

	/* replacement */
	return (dns_name_fromwire(&name, source, dctx, downcase, target));
}

static dns_result_t
towire_in_naptr(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	dns_name_t name;
	isc_region_t sr;

	REQUIRE(rdata->type == 35);
	REQUIRE(rdata->rdclass == 1);

	if (dns_compress_getedns(cctx) >= 1)
		dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
	else
		dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	/* priority, weight */
	dns_rdata_toregion(rdata, &sr);
	RETERR(mem_tobuffer(target, sr.base, 4));
	isc_region_consume(&sr, 4);
	
	/* flags */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/* service */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/* regexp */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/* replacement */
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &sr);
	return (dns_name_towire(&name, cctx, target));
}

static int
compare_in_naptr(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	int result;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == 35);
	REQUIRE(rdata1->rdclass == 1);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	/* priority, weight */
	result = memcmp(region1.base, region2.base, 4);
	if (result != 0)
		return (result < 0 ? -1 : 1);
	isc_region_consume(&region1, 4);
	isc_region_consume(&region2, 4);

	/* flags */
	result = memcmp(region1.base, region2.base, region1.base[0] + 1);
	if (result != 0)
		return (result < 0 ? -1 : 1);
	isc_region_consume(&region1, region1.base[0] + 1);
	isc_region_consume(&region2, region2.base[0] + 1);

	/* service */
	result = memcmp(region1.base, region2.base, region1.base[0] + 1);
	if (result != 0)
		return (result < 0 ? -1 : 1);
	isc_region_consume(&region1, region1.base[0] + 1);
	isc_region_consume(&region2, region2.base[0] + 1);

	/* regexp */
	result = memcmp(region1.base, region2.base, region1.base[0] + 1);
	if (result != 0)
		return (result < 0 ? -1 : 1);
	isc_region_consume(&region1, region1.base[0] + 1);
	isc_region_consume(&region2, region2.base[0] + 1);

	/* replacement */
	dns_name_init(&name1, NULL);
	dns_name_init(&name2, NULL);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return (dns_name_rdatacompare(&name1, &name2));
}

static dns_result_t
fromstruct_in_naptr(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		    void *source, isc_buffer_t *target)
{

	REQUIRE(type == 35);
	REQUIRE(rdclass == 1);

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_in_naptr(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {

	REQUIRE(rdata->type == 35);
	REQUIRE(rdata->rdclass == 1);

	target = target;
	mctx = mctx;

	return (DNS_R_NOTIMPLEMENTED);
}

static void
freestruct_in_naptr(void *source) {
	REQUIRE(source != NULL);
	REQUIRE(ISC_FALSE);
}

static dns_result_t
additionaldata_in_naptr(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
			void *arg)
{
	REQUIRE(rdata->type == 35);
	REQUIRE(rdata->rdclass == 1);

	(void)add;
	(void)arg;

	return (DNS_R_SUCCESS);
}

#endif	/* RDATA_IN_1_NAPTR_35_C */
