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

#define FILE_PATH							"crypto/hashing/self-test.c"

#include "./self-test.h"

#if (LS_SELFTEST && LS_SELFTEST_CRYPTO_HASHING)

#include "../../core/memory.h"
#include "../../debug/__self-test_logging.h"
#include "./_signatures.h"
#include "./sha2.h"
#include "./md5.h"
#include <string.h>


ID("BIST: cryptographic hash functions");


static const char *vectors[] = {
	"",
	"The quick brown fox jumps over the lazy dog",
	"The quick brown fox jumps over the lazy dog.",
	"Love is giving someone the power to destroy you, and trusting them not to",
	"Love is giving someone the power to destroy you, and trusting them not to.",
	"This is a test string that is /so/ original that no one has ever used it anywhere before.",
	NULL
};

static const ls_sha2_224_digest_t samples_sha2_224[] = {
	{ 0xD1, 0x4A, 0x02, 0x8C, 0x2A, 0x3A, 0x2B, 0xC9, 0x47, 0x61, 0x02, 0xBB, 0x28, 0x82, 0x34, 0xC4, 0x15, 0xA2, 0xB0, 0x1F, 0x82, 0x8E, 0xA6, 0x2A, 0xC5, 0xB3, 0xE4, 0x2F },
	{ 0x73, 0x0E, 0x10, 0x9B, 0xD7, 0xA8, 0xA3, 0x2B, 0x1C, 0xB9, 0xD9, 0xA0, 0x9A, 0xA2, 0x32, 0x5D, 0x24, 0x30, 0x58, 0x7D, 0xDB, 0xC0, 0xC3, 0x8B, 0xAD, 0x91, 0x15, 0x25 },
	{ 0x61, 0x9C, 0xBA, 0x8E, 0x8E, 0x05, 0x82, 0x6E, 0x9B, 0x8C, 0x51, 0x9C, 0x0A, 0x5C, 0x68, 0xF4, 0xFB, 0x65, 0x3E, 0x8A, 0x3D, 0x8A, 0xA0, 0x4B, 0xB2, 0xC8, 0xCD, 0x4C },
	{ 0x09, 0x9D, 0x2A, 0x8F, 0x6C, 0x30, 0xE5, 0x2F, 0x60, 0xD3, 0xA3, 0x67, 0x92, 0xB9, 0x66, 0xA6, 0xA2, 0x4D, 0x14, 0x08, 0x51, 0x4C, 0xF3, 0xD8, 0xA8, 0xBA, 0xB2, 0x8F },
	{ 0x3C, 0xF0, 0x8A, 0xD0, 0x26, 0x42, 0xAB, 0x40, 0xA4, 0x65, 0xAB, 0xE9, 0xB4, 0xD3, 0x3E, 0xDB, 0xAC, 0x0A, 0xF6, 0x2E, 0x6E, 0x36, 0x43, 0x58, 0x4D, 0x6A, 0x08, 0x24 },
	{ 0x52, 0x7E, 0x53, 0x71, 0xA3, 0xD9, 0x16, 0x44, 0xE7, 0x06, 0xE9, 0xCD, 0x51, 0xFC, 0x7A, 0x44, 0xF3, 0xC5, 0xA6, 0xC4, 0x91, 0xBE, 0xE8, 0x0F, 0x76, 0x10, 0xD8, 0xFF }
};

static const ls_sha2_256_digest_t samples_sha2_256[] = {
	{ 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55 },
	{ 0xD7, 0xA8, 0xFB, 0xB3, 0x07, 0xD7, 0x80, 0x94, 0x69, 0xCA, 0x9A, 0xBC, 0xB0, 0x08, 0x2E, 0x4F, 0x8D, 0x56, 0x51, 0xE4, 0x6D, 0x3C, 0xDB, 0x76, 0x2D, 0x02, 0xD0, 0xBF, 0x37, 0xC9, 0xE5, 0x92 },
	{ 0xEF, 0x53, 0x7F, 0x25, 0xC8, 0x95, 0xBF, 0xA7, 0x82, 0x52, 0x65, 0x29, 0xA9, 0xB6, 0x3D, 0x97, 0xAA, 0x63, 0x15, 0x64, 0xD5, 0xD7, 0x89, 0xC2, 0xB7, 0x65, 0x44, 0x8C, 0x86, 0x35, 0xFB, 0x6C },
	{ 0x07, 0x9D, 0xEA, 0x8F, 0xC9, 0xDD, 0xAA, 0x20, 0x23, 0xC2, 0x22, 0x60, 0x96, 0xE7, 0x6F, 0x0A, 0xBF, 0x64, 0x2A, 0x90, 0x67, 0x7B, 0xA2, 0xEB, 0xB6, 0x3B, 0x91, 0xF4, 0xD9, 0xEB, 0xA6, 0xED },
	{ 0xEE, 0xA8, 0x92, 0xC0, 0xB0, 0xD7, 0xF4, 0x63, 0x67, 0xE1, 0x8D, 0x50, 0x48, 0xCF, 0xDB, 0x06, 0x8B, 0x44, 0x43, 0x44, 0xDA, 0x02, 0x01, 0x9C, 0xF5, 0xAF, 0xCA, 0x34, 0xFB, 0x17, 0xA7, 0x0A },
	{ 0x60, 0xAA, 0x89, 0x25, 0xC9, 0x85, 0x63, 0x6F, 0x5B, 0xC9, 0x9A, 0x03, 0x97, 0xC0, 0x1A, 0xAD, 0x66, 0x3C, 0x36, 0xB7, 0xB3, 0x00, 0xAE, 0x7A, 0xDC, 0x90, 0xB9, 0x13, 0x30, 0x35, 0x01, 0x69 }
};

static const ls_sha2_384_digest_t samples_sha2_384[] = {
	{ 0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B },
	{ 0xCA, 0x73, 0x7F, 0x10, 0x14, 0xA4, 0x8F, 0x4C, 0x0B, 0x6D, 0xD4, 0x3C, 0xB1, 0x77, 0xB0, 0xAF, 0xD9, 0xE5, 0x16, 0x93, 0x67, 0x54, 0x4C, 0x49, 0x40, 0x11, 0xE3, 0x31, 0x7D, 0xBF, 0x9A, 0x50, 0x9C, 0xB1, 0xE5, 0xDC, 0x1E, 0x85, 0xA9, 0x41, 0xBB, 0xEE, 0x3D, 0x7F, 0x2A, 0xFB, 0xC9, 0xB1 },
	{ 0xED, 0x89, 0x24, 0x81, 0xD8, 0x27, 0x2C, 0xA6, 0xDF, 0x37, 0x0B, 0xF7, 0x06, 0xE4, 0xD7, 0xBC, 0x1B, 0x57, 0x39, 0xFA, 0x21, 0x77, 0xAA, 0xE6, 0xC5, 0x0E, 0x94, 0x66, 0x78, 0x71, 0x8F, 0xC6, 0x7A, 0x7A, 0xF2, 0x81, 0x9A, 0x02, 0x1C, 0x2F, 0xC3, 0x4E, 0x91, 0xBD, 0xB6, 0x34, 0x09, 0xD7 },
	{ 0x6F, 0x37, 0x5C, 0x2B, 0x6E, 0xF8, 0xEC, 0xFE, 0xCF, 0x41, 0x44, 0x27, 0x40, 0x73, 0xF4, 0xF8, 0x5F, 0x3E, 0x70, 0xC2, 0x75, 0x5C, 0x04, 0x64, 0x4E, 0x11, 0x26, 0xEC, 0xC7, 0x08, 0xAF, 0x37, 0xEF, 0x6B, 0xF9, 0xB2, 0x8B, 0xED, 0xEC, 0x7F, 0x0E, 0x3F, 0x10, 0x5E, 0x86, 0x12, 0xE8, 0x9D },
	{ 0x79, 0x39, 0x47, 0x2B, 0x98, 0xB1, 0xEC, 0x62, 0xC8, 0x18, 0xF8, 0x7B, 0x7F, 0x65, 0x48, 0x6E, 0xB9, 0xBB, 0xC3, 0x43, 0x59, 0x7D, 0xAE, 0xE6, 0xA2, 0x5E, 0x87, 0xC9, 0x2D, 0x54, 0x64, 0x32, 0x78, 0x48, 0x33, 0x1A, 0x80, 0x16, 0xC8, 0xEF, 0x5C, 0x49, 0x3C, 0xD6, 0xDA, 0x54, 0xD2, 0x99 },
	{ 0xD4, 0x3D, 0xB9, 0xFF, 0x47, 0x08, 0xDA, 0x1D, 0x93, 0x72, 0x8C, 0x93, 0xDC, 0xD4, 0x5A, 0xA6, 0x19, 0xC3, 0xE6, 0x96, 0xB5, 0xFD, 0x9B, 0x2D, 0x13, 0x93, 0x93, 0xE2, 0x96, 0x9E, 0x08, 0xD3, 0x81, 0x1D, 0x66, 0x8E, 0xD6, 0x0A, 0x8F, 0x35, 0xE6, 0x1B, 0x24, 0x42, 0x0B, 0x10, 0xD9, 0xA9 }
};

static const ls_sha2_512_digest_t samples_sha2_512[] = {
	{ 0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD, 0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D, 0x80, 0x07, 0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC, 0x83, 0xF4, 0xA9, 0x21, 0xD3, 0x6C, 0xE9, 0xCE, 0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0, 0xFF, 0x83, 0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F, 0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81, 0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E },
	{ 0x07, 0xE5, 0x47, 0xD9, 0x58, 0x6F, 0x6A, 0x73, 0xF7, 0x3F, 0xBA, 0xC0, 0x43, 0x5E, 0xD7, 0x69, 0x51, 0x21, 0x8F, 0xB7, 0xD0, 0xC8, 0xD7, 0x88, 0xA3, 0x09, 0xD7, 0x85, 0x43, 0x6B, 0xBB, 0x64, 0x2E, 0x93, 0xA2, 0x52, 0xA9, 0x54, 0xF2, 0x39, 0x12, 0x54, 0x7D, 0x1E, 0x8A, 0x3B, 0x5E, 0xD6, 0xE1, 0xBF, 0xD7, 0x09, 0x78, 0x21, 0x23, 0x3F, 0xA0, 0x53, 0x8F, 0x3D, 0xB8, 0x54, 0xFE, 0xE6 },
	{ 0x91, 0xEA, 0x12, 0x45, 0xF2, 0x0D, 0x46, 0xAE, 0x9A, 0x03, 0x7A, 0x98, 0x9F, 0x54, 0xF1, 0xF7, 0x90, 0xF0, 0xA4, 0x76, 0x07, 0xEE, 0xB8, 0xA1, 0x4D, 0x12, 0x89, 0x0C, 0xEA, 0x77, 0xA1, 0xBB, 0xC6, 0xC7, 0xED, 0x9C, 0xF2, 0x05, 0xE6, 0x7B, 0x7F, 0x2B, 0x8F, 0xD4, 0xC7, 0xDF, 0xD3, 0xA7, 0xA8, 0x61, 0x7E, 0x45, 0xF3, 0xC4, 0x63, 0xD4, 0x81, 0xC7, 0xE5, 0x86, 0xC3, 0x9A, 0xC1, 0xED },
	{ 0x7E, 0x9A, 0x2A, 0x2C, 0x27, 0x94, 0xF2, 0x78, 0x2C, 0x07, 0x1C, 0x48, 0xD1, 0xC7, 0x8C, 0x52, 0xAB, 0x0D, 0x26, 0xED, 0x5B, 0x3A, 0xCE, 0x89, 0x36, 0xBC, 0x19, 0x6A, 0x52, 0x63, 0x81, 0x90, 0x43, 0x4D, 0x9B, 0x4D, 0xC8, 0x23, 0x8F, 0x8D, 0x87, 0xF2, 0x4B, 0xB0, 0x65, 0x2F, 0xD6, 0xC5, 0x25, 0x3A, 0xA3, 0x79, 0x01, 0xFF, 0x6C, 0xCA, 0x8F, 0xFD, 0x80, 0xF8, 0x09, 0x9B, 0x2C, 0xB4 },
	{ 0xBC, 0xEA, 0x23, 0xA0, 0xA7, 0xA9, 0x30, 0xC1, 0x5B, 0x14, 0xBC, 0x04, 0x50, 0x17, 0x31, 0xA2, 0xAB, 0xCE, 0x5A, 0xB9, 0x33, 0xBA, 0xB5, 0xC9, 0x4B, 0x3E, 0x8D, 0xA4, 0x92, 0x95, 0x93, 0xB2, 0xC2, 0xF6, 0x9F, 0xBE, 0xBD, 0x03, 0x09, 0x4F, 0xD5, 0x9F, 0x42, 0x22, 0xE3, 0x68, 0x5D, 0x3E, 0x29, 0x31, 0xB8, 0xA5, 0xCB, 0xF9, 0xC2, 0xE3, 0xF9, 0xD7, 0x90, 0x83, 0x73, 0x6D, 0x65, 0x34 },
	{ 0xBB, 0x53, 0x37, 0x75, 0xEE, 0x29, 0xA1, 0x2E, 0x51, 0xFD, 0x9B, 0xBA, 0x80, 0x89, 0xC0, 0xCA, 0xA9, 0x5D, 0x19, 0x51, 0x6B, 0x56, 0x07, 0x1B, 0xE4, 0x0F, 0xAA, 0xBD, 0xB5, 0xD6, 0x08, 0xE7, 0xF3, 0x58, 0x7F, 0x38, 0x77, 0x68, 0x5B, 0x7B, 0x82, 0xDD, 0x6A, 0xE9, 0x10, 0xB1, 0x34, 0xEE, 0x1A, 0x92, 0xD3, 0x51, 0xBE, 0x99, 0x25, 0x22, 0xAB, 0x61, 0xCE, 0xBB, 0x55, 0x9B, 0x9D, 0xBD }
};

static const ls_md5_digest_t samples_md5[] = {
	{ 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04, 0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E },
	{ 0x9E, 0x10, 0x7D, 0x9D, 0x37, 0x2B, 0xB6, 0x82, 0x6B, 0xD8, 0x1D, 0x35, 0x42, 0xA4, 0x19, 0xD6 },
	{ 0xE4, 0xD9, 0x09, 0xC2, 0x90, 0xD0, 0xFB, 0x1C, 0xA0, 0x68, 0xFF, 0xAD, 0xDF, 0x22, 0xCB, 0xD0 },
	{ 0xA4, 0xC4, 0xAF, 0x0E, 0x0A, 0x9A, 0x39, 0xF5, 0x79, 0x89, 0x82, 0xE8, 0xB9, 0x12, 0x31, 0x22 },
	{ 0xC6, 0xE4, 0xD4, 0x64, 0x39, 0x62, 0x7C, 0x43, 0x7E, 0x60, 0xA3, 0x37, 0x60, 0xDB, 0xE9, 0x23 },
	{ 0x14, 0x80, 0x34, 0x63, 0xDC, 0xB1, 0x27, 0x0C, 0x70, 0x9F, 0xD3, 0x97, 0xE9, 0x37, 0xE8, 0x61 }
};


ls_result_t
static ls_test_crypto_hash(void *const hf_data, ls_hash_init_func_t const hf_init, ls_hash_update_func_t const hf_update, ls_hash_finish_func_t const hf_finish, ls_hash_clear_func_t const hf_clear, const void *const LS_RESTRICT input, const size_t input_size, const void *const LS_RESTRICT sample, const size_t sample_size) {
	LS_RESULT_CHECK_NULL(hf_data, 1);
	LS_RESULT_CHECK_NULL(hf_init, 2);
	LS_RESULT_CHECK_NULL(hf_update, 3);
	LS_RESULT_CHECK_NULL(hf_finish, 4);
	LS_RESULT_CHECK_NULL(hf_clear, 5);
	LS_RESULT_CHECK_NULL(input, 6);
	LS_RESULT_CHECK_NULL(sample, 7);
	LS_RESULT_CHECK_SIZE(sample_size, 1);

	ls_result_t result;

	if (!(result = hf_init(hf_data)).success) {
		return LS_RESULT_INHERITED(result, false);
	}

	if (!(result = hf_update(hf_data, input, input_size)).success) {
		return LS_RESULT_INHERITED(result, false);
	}

	uint8_t stackalloc(sample_buffer, sample_size);
	if (!(result = hf_finish(hf_data, sample_buffer)).success) {
		return LS_RESULT_INHERITED(result, false);
	}

	if (!(result = hf_clear(hf_data)).success) {
		return LS_RESULT_INHERITED(result, false);
	}

	if (memcmp(sample, sample_buffer, sample_size) == 0) {
		result = LS_RESULT_SUCCESS;
	} else {
		result = LS_RESULT_ERROR(LS_RESULT_CODE_DATA);
	}

	memset(sample_buffer, 0, sample_size);

	return result;
}


ls_bool
ls_selftest_crypto_hashing() {
	struct ls_sha2_32 sha2_32;
	struct ls_sha2_64 sha2_64;
	ls_md5_t md5;

	ls_nword_t i;
	const char *input = NULL;
	size_t input_size = 0;
	ls_bool passed = true;

	START_TEST("cryptographic hash functions");
	for (i = 0; (input = vectors[i]); ++i) {
		input_size = strlen(input);

		START_VECTOR(i, input);

		if (ls_test_crypto_hash(&sha2_32, (ls_hash_init_func_t)ls_sha2_224_init, (ls_hash_update_func_t)ls_sha2_224_update, (ls_hash_finish_func_t)ls_sha2_224_finish, (ls_hash_clear_func_t)ls_sha2_224_clear, input, input_size, samples_sha2_224[i], sizeof(*samples_sha2_224)).success) {
			TEST_SUB_PASSED("SHA-2-224");
		} else {
			TEST_SUB_FAILED("SHA-2-224");
			passed = false;
		}

		if (ls_test_crypto_hash(&sha2_32, (ls_hash_init_func_t)ls_sha2_256_init, (ls_hash_update_func_t)ls_sha2_256_update, (ls_hash_finish_func_t)ls_sha2_256_finish, (ls_hash_clear_func_t)ls_sha2_256_clear, input, input_size, samples_sha2_256[i], sizeof(*samples_sha2_256)).success) {
			TEST_SUB_PASSED("SHA-2-256");
		} else {
			TEST_SUB_FAILED("SHA-2-256");
			passed = false;
		}

		if (ls_test_crypto_hash(&sha2_64, (ls_hash_init_func_t)ls_sha2_384_init, (ls_hash_update_func_t)ls_sha2_384_update, (ls_hash_finish_func_t)ls_sha2_384_finish, (ls_hash_clear_func_t)ls_sha2_384_clear, input, input_size, samples_sha2_384[i], sizeof(*samples_sha2_384)).success) {
			TEST_SUB_PASSED("SHA-2-384");
		} else {
			TEST_SUB_FAILED("SHA-2-384");
			passed = false;
		}

		if (ls_test_crypto_hash(&sha2_64, (ls_hash_init_func_t)ls_sha2_512_init, (ls_hash_update_func_t)ls_sha2_512_update, (ls_hash_finish_func_t)ls_sha2_512_finish, (ls_hash_clear_func_t)ls_sha2_512_clear, input, input_size, samples_sha2_512[i], sizeof(*samples_sha2_512)).success) {
			TEST_SUB_PASSED("SHA-2-512");
		} else {
			TEST_SUB_FAILED("SHA-2-512");
			passed = false;
		}

		if (ls_test_crypto_hash(&md5, (ls_hash_init_func_t)ls_md5_init, (ls_hash_update_func_t)ls_md5_update, (ls_hash_finish_func_t)ls_md5_finish, (ls_hash_clear_func_t)ls_md5_clear, input, input_size, samples_md5[i], sizeof(*samples_md5)).success) {
			TEST_SUB_PASSED("MD5      ");
		} else {
			TEST_SUB_FAILED("MD5      ");
			passed = false;
		}
	}

	if (passed) {
		END_TEST_PASSED("cryptographic hash functions");
	} else {
		END_TEST_FAILED("cryptographic hash functions");
	}

	return passed;
}

#endif
