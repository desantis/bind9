#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <isc/thread.h>
#include <isc/mem.h>
#include <isc/hash.h>
#include <dns/name.h>
#include <dns/lowac.h>
#include <stdlib.h>

#include <ck_ht.h>
#include <ck_queue.h>


struct dns_lowac_entry {
    dns_name_t name;
    uint16_t flags;
    char* blob;
    uint32_t blobsize;
    CK_STAILQ_ENTRY(dns_lowac_entry) qentry;
};
    

struct dns_lowac {
    ck_ht_t ht;
    isc_mem_t *mctx;
    isc_thread_t thread;
    CK_STAILQ_HEAD(inqueue, dns_lowac_entry) inqueue; // = CK_STAILQ_HEAD_INITIALIZER(inqueue);
};

static void *
rthread(void* d);

static void *
ht_malloc(size_t r)
{

	return malloc(r);
}

static void
ht_free(void *p, size_t b, bool r)
{

	(void)b;
	(void)r;
	free(p);
	return;
}

static void
ht_hash_wrapper(struct ck_ht_hash *h,
	const void *key,
	size_t length,
	uint64_t seed)
{
        (void)seed;
	h->value = isc_hash_function(key, length, false, NULL);
	return;
}

static struct ck_malloc my_allocator = {
	.malloc = ht_malloc,
	.free = ht_free
};

static void *
rthread(void* d) {
    dns_lowac_t *lowac = (dns_lowac_t*) d;
    while (1) {
        dns_lowac_entry_t *entry = CK_STAILQ_FIRST(&lowac->inqueue);
        if (entry != NULL) {
            CK_STAILQ_REMOVE_HEAD(&lowac->inqueue, qentry);

            ck_ht_entry_t htentry;
            ck_ht_hash_t h;
            isc_region_t r;

            dns_name_toregion(&entry->name, &r);
            ck_ht_hash(&h, &lowac->ht, r.base, r.length);
            ck_ht_entry_set(&htentry, h, r.base, r.length, entry);
            if (ck_ht_get_spmc(&lowac->ht, h, &htentry) == false) {
//                printf("Lowac not found, puting\n");
                ck_ht_put_spmc(&lowac->ht, h, &htentry);
            } else {
//                printf("Lowac found, ignoring\n");
            }
        } else {
            usleep(1000);
        }
    }
    return NULL;
}

dns_lowac_t*
dns_lowac_create(isc_mem_t *mctx) {
    dns_lowac_t *lowac = malloc(sizeof(dns_lowac_t));
    CK_STAILQ_INIT(&lowac->inqueue);
    if (ck_ht_init(&lowac->ht, CK_HT_MODE_BYTESTRING | CK_HT_WORKLOAD_DELETE, ht_hash_wrapper, &my_allocator, 32, 131423123) == false) {
        abort();
    }
    lowac->mctx = mctx;
    isc_thread_create(rthread, lowac, &lowac->thread);
    return lowac;
}

isc_result_t
dns_lowac_put(dns_lowac_t *lowac, dns_name_t *name, char* packet, int size) {
    dns_lowac_entry_t *entry = malloc(sizeof(*entry));
    dns_name_init(&entry->name, NULL);
    dns_name_dup(name, lowac->mctx, &entry->name);
    entry->blob = malloc(size);
    memcpy(entry->blob, packet, size);
    entry->blobsize = size;
//    printf("LOWAC PUT %p %d\n", entry->blob, size);
    CK_STAILQ_INSERT_TAIL(&lowac->inqueue, entry, qentry);
    return (ISC_R_SUCCESS);
}

isc_result_t
dns_lowac_get(dns_lowac_t *lowac, dns_name_t *name, char* blob, int* blobsize, bool tcp) {
	ck_ht_entry_t htentry;
	ck_ht_hash_t h;
	isc_region_t r;

	dns_name_toregion(name, &r);
	ck_ht_hash(&h, &lowac->ht, r.base, r.length);
	ck_ht_entry_key_set(&htentry, r.base, r.length);
        if (ck_ht_get_spmc(&lowac->ht, h, &htentry) == false) {
        	return (ISC_R_NOTFOUND);
	} else {
		dns_lowac_entry_t *entry = ck_ht_entry_value(&htentry);
		if (tcp) {
    		    blob[0] = entry->blobsize >> 8;
    		    blob[1] = entry->blobsize;
    		    memcpy(blob+2, entry->blob, entry->blobsize);
    		    *blobsize = entry->blobsize + 2;
                } else {
    		    memcpy(blob, entry->blob, entry->blobsize);
    		    *blobsize = entry->blobsize;
                }
//                printf("LOWAC GET %p %d\n", blob, *blobsize);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_FAILURE);
}    
