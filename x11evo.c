#include "cpuminer-config.h"
#include "miner.h"


#include <string.h>
#include <stdint.h>

#include "sph/sph_blake.h"
#include "sph/sph_bmw.h"
#include "sph/sph_groestl.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"
#include "sph/sph_skein.h"
#include "sph/sph_luffa.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_shavite.h"
#include "sph/sph_simd.h"
#include "sph/sph_echo.h"

#define INITIAL_DATE 1462060800
#define HASH_FUNC_COUNT 11


/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context    blake1;
	sph_bmw512_context      bmw1;
	sph_groestl512_context  groestl1;
	sph_skein512_context    skein1;
	sph_jh512_context       jh1;
	sph_keccak512_context   keccak1;
	sph_luffa512_context    luffa1;
	sph_cubehash512_context cubehash1;
	sph_shavite512_context  shavite1;
	sph_simd512_context     simd1;
	sph_echo512_context     echo1;
} Xhash_context_holder;

static Xhash_context_holder base_contexts;


void init_Xhash_contexts()
{
	sph_blake512_init(&base_contexts.blake1);
	sph_bmw512_init(&base_contexts.bmw1);
	sph_groestl512_init(&base_contexts.groestl1);
	sph_skein512_init(&base_contexts.skein1);
	sph_jh512_init(&base_contexts.jh1);
	sph_keccak512_init(&base_contexts.keccak1);
	sph_luffa512_init(&base_contexts.luffa1);
	sph_cubehash512_init(&base_contexts.cubehash1);
	sph_shavite512_init(&base_contexts.shavite1);
	sph_simd512_init(&base_contexts.simd1);
	sph_echo512_init(&base_contexts.echo1);
}


uint32_t getCurrentAlgoSeq(uint32_t current_time, uint32_t base_time) {
	return (current_time - base_time) / (60 * 60 * 24);
}

void swap(uint8_t *a, uint8_t *b) {
	uint8_t __tmp = *a;
	*a = *b;
	*b = __tmp;
}

void initPerm(uint8_t n[], uint8_t count) {
	int i;
	for (i = 0; i<count; i++)
		n[i] = i;
}

int nextPerm(uint8_t n[], uint32_t count) {
	uint32_t tail, i, j;

	if (count <= 1)
		return 0;

	for (i = count - 1; i>0 && n[i - 1] >= n[i]; i--);
	tail = i;

	if (tail > 0) {
		for (j = count - 1; j>tail && n[j] <= n[tail - 1]; j--);
		swap(&n[tail - 1], &n[j]);
	}

	for (i = tail, j = count - 1; i<j; i++, j--)
		swap(&n[i], &n[j]);

	return (tail != 0);
}


void getAlgoString(char *str, uint32_t count)
{
	uint8_t algoList[HASH_FUNC_COUNT];
	char s[100];
	char *sptr;

	initPerm(algoList, HASH_FUNC_COUNT);

	int j;

	int k;
	for (k = 0; k < count; k++) {
		nextPerm(algoList, HASH_FUNC_COUNT);
	}

	sptr = str;
	for (j = 0; j < HASH_FUNC_COUNT; j++) {
		if (algoList[j] >= 10)
			sprintf(sptr, "%c", 'A' + (algoList[j] - 10));
		else
			sprintf(sptr, "%u", algoList[j]);
		sptr++;
	}
	*sptr = 0;

	//applog(LOG_DEBUG, "nextPerm %s", str);
}



void evocoin_twisted_code(char *result, const unsigned char *ntimebin, char *code)
{
	uint32_t h32, *be32 = (uint32_t *)ntimebin;
	h32 = be32toh(*be32);
	
	uint32_t count = getCurrentAlgoSeq(h32, INITIAL_DATE);

	getAlgoString(code, count);

	sprintf(result, "_%d_%s_", count, code);
}


/*
* Encode a length len/4 vector of (uint32_t) into a length len vector of
* (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
*/
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}


static inline void Xhash(void *state, const void *input, const unsigned char *ntimebin)
{
	init_Xhash_contexts();

	Xhash_context_holder ctx;

	uint32_t hashA[16], hashB[16];
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	char completeCode[64];
	char resultCode[HASH_FUNC_COUNT + 1];
	evocoin_twisted_code(completeCode, ntimebin, resultCode);

	int i;
	for (i = 0; i < strlen(resultCode); i++) {
		char elem = resultCode[i];
		uint8_t idx;
		if (elem >= 'A')
			idx = elem - 'A' + 10;
		else
			idx = elem - '0';

		const void *in;
		void *out;
		int size;

		if (i == 0) {
			in = input;
			size = 80;
			out = hashA;
		}
		else {
			if (out == hashA) {
				in = hashA;
				out = hashB;
			}
			else {
				in = hashB;
				out = hashA;
			}
			size = 64;
		}

		switch (idx) {
		case 0:
			sph_blake512(&ctx.blake1, in, size);
			sph_blake512_close(&ctx.blake1, out);
			break;
		case 1:
			sph_bmw512(&ctx.bmw1, in, size);
			sph_bmw512_close(&ctx.bmw1, out);
			break;
		case 2:
			sph_groestl512(&ctx.groestl1, in, size);
			sph_groestl512_close(&ctx.groestl1, out);
			break;
		case 3:
			sph_skein512(&ctx.skein1, in, size);
			sph_skein512_close(&ctx.skein1, out);
			break;
		case 4:
			sph_jh512(&ctx.jh1, in, size);
			sph_jh512_close(&ctx.jh1, out);
			break;
		case 5:
			sph_keccak512(&ctx.keccak1, in, size);
			sph_keccak512_close(&ctx.keccak1, out);
			break;
		case 6:
			sph_luffa512(&ctx.luffa1, in, size);
			sph_luffa512_close(&ctx.luffa1, out);
			break;
		case 7:
			sph_cubehash512(&ctx.cubehash1, in, size);
			sph_cubehash512_close(&ctx.cubehash1, out);
			break;
		case 8:
			sph_shavite512(&ctx.shavite1, in, size);
			sph_shavite512_close(&ctx.shavite1, out);
			break;
		case 9:
			sph_simd512(&ctx.simd1, in, size);
			sph_simd512_close(&ctx.simd1, out);
			break;
		case 10:
			sph_echo512(&ctx.echo1, in, size);
			sph_echo512_close(&ctx.echo1, out);
			break;
		}

	}

	memcpy(state, hashA, 32);

}

static const uint32_t diff1targ = 0x0000ffff;


int scanhash_X11EVO(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done, const unsigned char* ntimebin) {

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];


	int kk = 0;

#pragma unroll
	for (; kk < 32; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
	if (ptarget[7] == 0) {
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			Xhash(hash64, &endiandata, ntimebin);
			if (((hash64[7] & 0xFFFFFFFF) == 0) &&
				fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}
	else if (ptarget[7] <= 0xF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			Xhash(hash64, &endiandata, ntimebin);
			if (((hash64[7] & 0xFFFFFFF0) == 0) &&
				fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}
	else if (ptarget[7] <= 0xFF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			Xhash(hash64, &endiandata, ntimebin);
			if (((hash64[7] & 0xFFFFFF00) == 0) &&
				fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}
	else if (ptarget[7] <= 0xFFF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			Xhash(hash64, &endiandata, ntimebin);
			if (((hash64[7] & 0xFFFFF000) == 0) &&
				fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);

	}
	else if (ptarget[7] <= 0xFFFF)
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			Xhash(hash64, &endiandata, ntimebin);
			if (((hash64[7] & 0xFFFF0000) == 0) &&
				fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);

	}
	else
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n);
			Xhash(hash64, &endiandata, ntimebin);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}














