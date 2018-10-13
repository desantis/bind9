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
#include <ck_fifo.h>


struct dns_lowac_entry {
    dns_name_t name;
    uint16_t flags;
    char* blob;
    uint32_t blobsize;
};
    

struct dns_lowac {
    ck_ht_t ht;
    isc_mem_t *mctx;
    isc_thread_t thread;
    int count;
    ck_fifo_mpmc_entry_t mpmc_stub;
    ck_fifo_mpmc_t inqueue;
};

static void *
rthread(void* d);

static void *
ht_malloc(size_t r)
{

//        printf("HT malloc %lu\n", r);
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
        dns_lowac_entry_t *entry = NULL;
        ck_fifo_mpmc_entry_t *garbage = NULL;
        if (ck_fifo_mpmc_dequeue(&lowac->inqueue, &entry, &garbage) == true) {
//            printf("%p Entry non null %p %p\n", lowac, entry, garbage);
            if (garbage != &lowac->mpmc_stub)
                free(garbage);
            ck_ht_entry_t htentry;
            ck_ht_hash_t h;
            isc_region_t r;

            dns_name_toregion(&entry->name, &r);
            ck_ht_hash(&h, &lowac->ht, r.base, r.length);
            ck_ht_entry_set(&htentry, h, r.base, r.length, entry);
            if (ck_ht_get_spmc(&lowac->ht, h, &htentry) == false) {
//                printf("Lowac not found, puting\n");
                ck_ht_put_spmc(&lowac->ht, h, &htentry);
                lowac->count++;
            } else {
                dns_name_free(&entry->name, lowac->mctx);
                free(entry->blob);
                free(entry);
//                printf("Lowac found, ignoring\n");
            }
            isc_thread_yield();
        } else {
            usleep(10000);
        }
    }
    return NULL;
}
dns_lowac_t*
dns_lowac_create(isc_mem_t *mctx) {
    dns_lowac_t *lowac = malloc(sizeof(dns_lowac_t));
    ck_fifo_mpmc_init(&lowac->inqueue, &lowac->mpmc_stub);
    lowac->count = 0;
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
    ck_fifo_mpmc_entry_t *qentry = malloc(sizeof(ck_fifo_mpmc_entry_t));
//    printf("LOWAC PUT %p %p %d\n", entry, qentry, size);
    ck_fifo_mpmc_enqueue(&lowac->inqueue, qentry, entry);
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
