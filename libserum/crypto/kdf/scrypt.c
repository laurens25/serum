/*******************************************************************************
**                                                                            **
**   The MIT License                                                          **
**                                                                            **
**   Copyright 2017 icecubetray                                               **
**                                                                            **
**   Permission is hereby granted, free of charge, to any person              **
**   obtaining a copy of this software and associated documentation files     **
**   (the "Software"), to deal in the Software without restriction,           **
**   including without limitation the rights to use, copy, modify, merge,     **
**   publish, distribute, sublicense, and/or sell copies of the Software,     **
**   and to permit persons to whom the Software is furnished to do so,        **
**   subject to the following conditions:                                     **
**                                                                            **
**   The above copyright notice and this permission notice shall be           **
**   included in all copies or substantial portions of the Software.          **
**                                                                            **
**   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,          **
**   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF       **
**   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.   **
**   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY     **
**   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,     **
**   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        **
**   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                   **
**                                                                            **
********************************************************************************
**
**  Notes:
**    -
**
*/

#define FILE_PATH							"crypto/kdf/scrypt.c"

#include "./scrypt.h"
#include "./pbkdf2-sha2.h"


static void salsa208_word_specification(uint32_t inout[16])
{
	int i;
	uint32_t x[16];
	memcpy(x, inout, sizeof(x));
	for (i = 8; i > 0; i -= 2) {
		x[ 4] ^= LS_ROTL32(x[ 0] + x[12],  7);
		x[ 8] ^= LS_ROTL32(x[ 4] + x[ 0],  9);
		x[12] ^= LS_ROTL32(x[ 8] + x[ 4], 13);
		x[ 0] ^= LS_ROTL32(x[12] + x[ 8], 18);
		x[ 9] ^= LS_ROTL32(x[ 5] + x[ 1],  7);
		x[13] ^= LS_ROTL32(x[ 9] + x[ 5],  9);
		x[ 1] ^= LS_ROTL32(x[13] + x[ 9], 13);
		x[ 5] ^= LS_ROTL32(x[ 1] + x[13], 18);
		x[14] ^= LS_ROTL32(x[10] + x[ 6],  7);
		x[ 2] ^= LS_ROTL32(x[14] + x[10],  9);
		x[ 6] ^= LS_ROTL32(x[ 2] + x[14], 13);
		x[10] ^= LS_ROTL32(x[ 6] + x[ 2], 18);
		x[ 3] ^= LS_ROTL32(x[15] + x[11],  7);
		x[ 7] ^= LS_ROTL32(x[ 3] + x[15],  9);
		x[11] ^= LS_ROTL32(x[ 7] + x[ 3], 13);
		x[15] ^= LS_ROTL32(x[11] + x[ 7], 18);
		x[ 1] ^= LS_ROTL32(x[ 0] + x[ 3],  7);
		x[ 2] ^= LS_ROTL32(x[ 1] + x[ 0],  9);
		x[ 3] ^= LS_ROTL32(x[ 2] + x[ 1], 13);
		x[ 0] ^= LS_ROTL32(x[ 3] + x[ 2], 18);
		x[ 6] ^= LS_ROTL32(x[ 5] + x[ 4],  7);
		x[ 7] ^= LS_ROTL32(x[ 6] + x[ 5],  9);
		x[ 4] ^= LS_ROTL32(x[ 7] + x[ 6], 13);
		x[ 5] ^= LS_ROTL32(x[ 4] + x[ 7], 18);
		x[11] ^= LS_ROTL32(x[10] + x[ 9],  7);
		x[ 8] ^= LS_ROTL32(x[11] + x[10],  9);
		x[ 9] ^= LS_ROTL32(x[ 8] + x[11], 13);
		x[10] ^= LS_ROTL32(x[ 9] + x[ 8], 18);
		x[12] ^= LS_ROTL32(x[15] + x[14],  7);
		x[13] ^= LS_ROTL32(x[12] + x[15],  9);
		x[14] ^= LS_ROTL32(x[13] + x[12], 13);
		x[15] ^= LS_ROTL32(x[14] + x[13], 18);
	}

	for (i = 0; i < 16; ++i){
		inout[i] += x[i];
	}

	memset(x, 0, sizeof(x));
}


static void 
scryptBlockMix(uint32_t *B_, uint32_t *B, uint64_t r)
{
	uint64_t i, j;
	uint32_t X[16], *pB;

	memcpy(X, B + (r * 2 - 1) * 16, sizeof(X));
	pB = B;
	for (i = 0; i < r * 2; i++) {
		for (j = 0; j < 16; j++)
			X[j] ^= *pB++;
		salsa208_word_specification(X);
		
		memcpy(B_ + (i / 2 + (i & 1) * r) * 16, X, sizeof(X));
	}

	memset(X, 0, sizeof(X));
}


static void
scryptROMix(unsigned char *B, uint64_t r, uint64_t N, uint32_t *X, uint32_t *T, uint32_t *V) {
	unsigned char *pB;
	uint32_t *pV;
	uint64_t i, k;

	// Convert from little endian input
	for (pV = V, i = 0, pB = B; i < 32 * r; i++, pV++) {
		*pV = *pB++;
		*pV |= *pB++ << 8;
		*pV |= *pB++ << 16;
		*pV |= (uint32_t)*pB++ << 24;
	}

	for (i = 1; i < N; i++, pV += 32 * r)
		scryptBlockMix(pV, pV - 32 * r, r);

	scryptBlockMix(X, V + (N - 1) * 32 * r, r);

	for (i = 0; i < N; i++) {
		uint32_t j;
		j = X[16 * (2 * r - 1)] % N;
		pV = V + 32 * r * j;
		for (k = 0; k < 32 * r; k++)
			T[k] = X[k] ^ *pV++;
		scryptBlockMix(X, T, r);
	}

	// Convert output to little endian
	for (i = 0, pB = B; i < 32 * r; i++) {
		uint32_t xtmp = X[i];
		*pB++ = xtmp & 0xFF;
		*pB++ = (xtmp >> 8) & 0xFF;
		*pB++ = (xtmp >> 16) & 0xFF;
		*pB++ = (xtmp >> 24) & 0xFF;
	}
}


ls_result_t
ls_scrypt(unsigned char *out, size_t out_size, const char *pass, size_t pass_size, const unsigned char *salt, size_t salt_size, uint64_t N, uint64_t r, uint64_t p, size_t mem_max) {
	LS_RESULT_CHECK_NULL(out, 1);
	LS_RESULT_CHECK_SIZE(out_size, 1);
	LS_RESULT_CHECK_NULL(pass, 2);
	LS_RESULT_CHECK_NULL(salt, 3);


	if (N < 2 || (N & (N - 1))) {
		return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_DATA, 1);
	}

	if (p > ((1 << 30) - 1)) {
		return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_DATA, 2);
	}

	if ((16 * r) <= (((sizeof(uint64_t) * 8) - 1))) {
		if (N >= (((uint64_t)1) << (16 * r))) {
			return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_DATA, 3);
		}
	}

	uint64_t i = (UINT64_MAX / 128);
	if (N + 2 > i / r) {
		return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_DATA, 4);
	}


	uint64_t
		Blen = (p * 128 * r),
		Vlen = (32 * r * (N + 2) * sizeof(uint32_t));

	if (Blen > (UINT64_MAX - Vlen) || Blen > (SIZE_MAX - Vlen)) {
		return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_DATA, 5);
	}


	size_t allocsize = ((size_t)(Blen + Vlen));
	if (allocsize > mem_max) {
		return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_ALLOCATION, 1);
	}

	uint8_t *B = malloc(allocsize);
	if (!B) {
		return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_ALLOCATION, 2);
	}


	if (ls_pbkdf2_sha2_256(out, out_size, pass, pass_size, salt, salt_size, 1).success) {
		uint32_t
			*X = ((uint32_t *)(B + Blen)),
			*T = (X + 32 * r),
			*V = (T + 32 * r);

		for (i = 0; i < p; i++) {
			scryptROMix((B + 128 * r * i), r, N, X, T, V);
		}

		if (ls_pbkdf2_sha2_256(out, out_size, pass, pass_size, B, (size_t)Blen, 1).success) {
			free(B);
			return LS_RESULT_SUCCESS;
		}
	}


	free(B);
	return LS_RESULT_ERROR(LS_RESULT_CODE_DATA);
}
