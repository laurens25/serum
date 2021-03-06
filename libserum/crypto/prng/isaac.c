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
**    Derived from Bob Jenkins' reference code.
**
*/

#define FILE_PATH                           "crypto/prng/isaac.c"

#include "./isaac.h"
#include <string.h>


ID("ISAAC implementation");


#define MIX()								\
	a ^= (b << 11); d += a; b += c;			\
	b ^= ((c & BITMASK(32)) >>  2);			\
	e += b; c += d; c ^= (d <<  8);			\
	f += c; d += e;							\
	d ^= ((e & BITMASK(32)) >> 16);			\
	g += d; e += f; e ^= (f << 10);			\
	h += e; f += g;							\
	f ^= ((g & BITMASK(32)) >>  4);			\
	a += f; g += h; g ^= (h <<  8);			\
	b += g; h += a;							\
	h ^= ((a & BITMASK(32)) >>  9);			\
	c += h; a += b;
#define ROUND()								\
	MIX();									\
	m[i    ] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d; \
	m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
#define ROUNDRSL(var)						\
	a += (var)[i    ]; b += (var)[i + 1];	\
	c += (var)[i + 2]; d += (var)[i + 3];	\
	e += (var)[i + 4]; f += (var)[i + 5];	\
	g += (var)[i + 6]; h += (var)[i + 7];	\
	ROUND();

ls_result_t
ls_isaac_init_ex(ls_isaac_t *const LS_RESTRICT ctx, const void *const LS_RESTRICT seed, const size_t size) {
	LS_RESULT_CHECK_NULL(ctx, 1);

	memset(ctx, 0, sizeof(*ctx));

	uint_fast32_t i = 0;
	uint32_t a, b, c, d, e, f, g, h,
		*m = ctx->mem,
		*r = ctx->rsl;

	a = b = c = d = e = f = g = h = 0x9E3779B9;

	for (i = 5; --i;) {
		MIX();
	}

	if (size) {
		if (seed) {
			memcpy(ctx->rsl, seed, size);
		} else {
			memset(ctx->rsl, 0, sizeof(ctx->rsl));
		}

		for (i = 0; i < LS_CRYPTO_PRNG_ISAAC_SIZE; i += 8) {
			ROUNDRSL(r);
		}
		for (i = 0; i < LS_CRYPTO_PRNG_ISAAC_SIZE; i += 8) {
			ROUNDRSL(m);
		}
	} else {
		for (i = 0; i < LS_CRYPTO_PRNG_ISAAC_SIZE; i += 8) {
			ROUND();
		}
	}

	if (ls_isaac_update(ctx).success) {
		return ls_isaac_update(ctx);
	} else {
		return LS_RESULT_ERROR(LS_RESULT_CODE_MISC);
	}
}


ls_result_t
ls_isaac_init(ls_isaac_t *const ctx) {
	return ls_isaac_init_ex(ctx, NULL, 1);
}


ls_result_t
ls_isaac_init_device(ls_isaac_t *const LS_RESTRICT ctx, const ls_device_t *const LS_RESTRICT device) {
	LS_RESULT_CHECK_NULL(ctx, 1);
	LS_RESULT_CHECK_NULL(device, 2);

	ls_result_t result;

	uint32_t seed[LS_CRYPTO_PRNG_ISAAC_SIZE];
	if (ls_device_generate(device, seed, sizeof(seed)).success) {
		result = ls_isaac_init_ex(ctx, seed, sizeof(seed));
	} else {
		result = LS_RESULT_ERROR(LS_RESULT_CODE_FUNCTION);
	}
	memset(seed, 0, sizeof(seed));

	return result;
}

#undef MIX
#undef ROUND
#undef ROUNDRSL


ls_result_t
ls_isaac_clear(ls_isaac_t *const ctx) {
	LS_RESULT_CHECK_NULL(ctx, 1);

	memset(ctx, 0, sizeof(*ctx));

	return LS_RESULT_SUCCESS;
}


#define ind(mm, x)  ((mm)[((x) >> 2) & (LS_CRYPTO_PRNG_ISAAC_SIZE - 1)])
#define STEP(mix)									\
	(x) = *(m);										\
	(a) = (((a) ^ (mix)) + *((m2)++));				\
	*((m)++) = (y) = (ind((mm), (x)) + (a) + (b));	\
	*((r)++) = (b) = (ind((mm), ((y) >> LS_CRYPTO_PRNG_ISAAC_SIZEL)) + (x)) & BITMASK(32);
#define ROUND()										\
	STEP((a << 13));								\
	STEP(((a & BITMASK(32)) >>  6));				\
	STEP((a <<  2));								\
	STEP(((a & BITMASK(32)) >> 16));

ls_result_t
ls_isaac_update(ls_isaac_t *const ctx) {
	LS_RESULT_CHECK_NULL(ctx, 1);

	uint32_t x, y, *m, *m2, *mend,
		a = ctx->a,
		b = (ctx->b + ++(ctx->c)),
		*mm = ctx->mem,
		*r = ctx->rsl;

	x = y = 0;
	m = m2 = mend = NULL;

	for (m = mm, mend = m2 = (m + (LS_CRYPTO_PRNG_ISAAC_SIZE >> 1)); m < mend;) {
		ROUND();
	}

	for (m2 = mm; m2 < mend;) {
		ROUND();
	}

	ctx->a = a;
	ctx->b = b;

	ctx->count = LS_CRYPTO_PRNG_ISAAC_SIZE;

	return LS_RESULT_SUCCESS;
}

#undef ind
#undef STEP
#undef ROUND


uint32_t
ls_isaac(ls_isaac_t *const ctx) {
	if (!ctx) {
		return 0;
	}

	if (!ctx->count--) {
		if (!ls_isaac_update(ctx).success) {
			return 0;
		}
		ctx->count = (LS_CRYPTO_PRNG_ISAAC_SIZE - 1);
	}

	return (uint32_t)(ctx->rsl[ctx->count] & BITMASK(32));
}


#if DEBUG
ls_result_t
ls_isaac_test() { // FIXME: move to selftest
	ls_result_t result = LS_RESULT_SUCCESS;

	ls_isaac_t ctx;
	if (ls_isaac_init(&ctx).success) {
		uint32_t vectors[512] = {
			0xF650E4C8, 0xE448E96D, 0x98DB2FB4, 0xF5FAD54F, 0x433F1AFB, 0xEDEC154A, 0xD8370487, 0x46CA4F9A,
			0x5DE3743E, 0x88381097, 0xF1D444EB, 0x823CEDB6, 0x6A83E1E0, 0x4A5F6355, 0xC7442433, 0x25890E2E,
			0x7452E319, 0x57161DF6, 0x38A824F3, 0x002ED713, 0x29F55449, 0x51C08D83, 0xD78CB99E, 0xA0CC74F3,
			0x8F651659, 0xCBC8B7C2, 0xF5F71C69, 0x12AD6419, 0xE5792E1B, 0x860536B8, 0x09B3CE98, 0xD45D6D81,
			0xF3B26129, 0x17E38F85, 0x29CF72CE, 0x349947B0, 0xC998F9FF, 0xB5E13DAE, 0x32AE2A2B, 0xF7CF814C,
			0x8EBFA303, 0xCF22E064, 0x0B923200, 0xECA4D58A, 0xEF53CEC4, 0xD0F7B37D, 0x9C411A2A, 0xFFDF8A80,
			0xB40E27BC, 0xB4D2F976, 0x44B89B08, 0xF37C71D5, 0x1A70E7E9, 0x0BDB9C30, 0x60DC5207, 0xB3C3F24B,
			0xD7386806, 0x229749B5, 0x4E232CD0, 0x91DABC65, 0xA70E1101, 0x8B87437E, 0x5781414F, 0xCDBC62E2,
			0x8107C9FF, 0x69D2E4AE, 0x3B18E752, 0xB143B688, 0x6F4E0772, 0x95138769, 0x943C3C74, 0xAFC17A97,
			0x0FD43963, 0x6A529B0B, 0xD8C58A6A, 0xA8BCC22D, 0x2DB35DFE, 0xA7A2F402, 0x6CB167DB, 0x538E1F4E,
			0x7275E277, 0x1D3B8E97, 0xECC5DC91, 0x15E3A5B9, 0x03696614, 0x30AB93EC, 0xAC9FE69D, 0x7BC76811,
			0x60EDA8DA, 0x28833522, 0xD5295EBC, 0x5ADB60E7, 0xF7E1CDD0, 0x97166D14, 0xB67EC13A, 0x210F3925,
			0x64AF0FEF, 0x0D028684, 0x3AEA3DEC, 0xB058BAFB, 0xB8B0CCFC, 0xF2B5CC05, 0xE3A662D9, 0x814BC24C,
			0x2364A1AA, 0x37C0ED05, 0x2B36505C, 0x451E7EC8, 0x5D2A542F, 0xE43D0FBB, 0x91C8D925, 0x60D4D5F8,
			0x12A0594B, 0x9E8A51DA, 0xCD49EBDB, 0x1B0DCDC1, 0xCD57C7F7, 0xE6344451, 0x7DED386F, 0x2F36FA86,
			0xA6D12101, 0x33BC405D, 0xB388D96C, 0xDB6DBE96, 0xFE29661C, 0x13EDC0CB, 0xCB0EEE4A, 0x70CC94AE,
			0xDE11ED34, 0x0606CF9F, 0x3A6CE389, 0x23D74F4E, 0xA37F63FF, 0x917BDEC2, 0xD73F72D4, 0x0E7E0E67,
			0x3D77D9A2, 0x13ADD922, 0x8891B3DB, 0x01A9BD70, 0x56A001E3, 0xD51F093D, 0xCC033CE3, 0x5AD0D3B0,
			0x34105A8C, 0x6A123F57, 0xBD2E5024, 0x7364944B, 0xE89B1A3B, 0x21835C4D, 0x9F39E2D9, 0xD405DED8,
			0x294D37E5, 0xBCCAAEED, 0x35A124B5, 0x6708A2BC, 0xB00960BA, 0x2A98121A, 0x4D8FAE82, 0x0BB3263F,
			0x12595A19, 0x6A107589, 0x0809E494, 0x21C171EC, 0x884D6825, 0x14C8009B, 0xB0B84E7B, 0x03FB88F4,
			0x28E7CB78, 0x9388B13B, 0xDD2DC1D5, 0x848F520A, 0x07C28CD1, 0x68A39358, 0x72C9137D, 0x127DD430,
			0xC613F157, 0x8C2F0D55, 0xF7D3F39F, 0x309BFB78, 0x8406B137, 0x46C0A6F5, 0x3718D597, 0x08607F04,
			0x76904B6D, 0x04DB4E13, 0xCD7411A7, 0xB510CE0E, 0xBFC7F7CC, 0xB83F957A, 0xFDFEF62D, 0xC35E4580,
			0x3FF1E524, 0x4112D96C, 0x02C9B944, 0xD5990DFB, 0xE7E26581, 0x0D9C7E7E, 0x826DFA89, 0x66F1E0AB,
			0x30BCC764, 0xEADEBEAC, 0xED35E5EE, 0x0C571A7D, 0xE4F3A26A, 0xF7F58F7B, 0xADF6BC23, 0x5D023E65,
			0x1ED3FF4E, 0xEC46B0B6, 0xD2A93B51, 0xE75B41C9, 0x7E315AEB, 0x61119A5A, 0x53245B79, 0x33F6D7B1,
			0xCAE8DEBA, 0x50FC8194, 0xAFA92A6D, 0xC87C8006, 0x4188BFCD, 0x8BACE62E, 0x78FFA568, 0x5597EC0F,
			0xB4415F7D, 0x08294766, 0xAD567643, 0x09C36F90, 0x3DDE9F39, 0x4A0A283C, 0x18080C8E, 0x080C79EC,
			0x79AE4C10, 0xCB9E1563, 0x7CDD662F, 0x62D31911, 0xA4CA0CF1, 0x5CF824CD, 0x3B708F99, 0x1E16614C,
			0xB6B9D766, 0x5DE87ABB, 0x7229EA81, 0xD5B2D750, 0x56E6CD21, 0xFE1E42D5, 0x96DA2655, 0xC2B9AA36,
			0xB8F6FD4A, 0x6A158D10, 0x01913FD3, 0xAF7D1FB8, 0x0B5E435F, 0x90C10757, 0x6554ABDA, 0x7A68710F,
			0x82AC484F, 0xD7E1C7BE, 0x95C85EAA, 0x94A302F4, 0x4D3CFBDA, 0x786B2908, 0x1010B275, 0x82D53D12,
			0x21E2A51C, 0x3D1E9150, 0xB059261D, 0xD0638E1A, 0x31860F05, 0x81F2864D, 0xFF4CFC35, 0x0451516D,
			0xBD086F26, 0xBC5654C1, 0x65DFA427, 0xA82427F5, 0x582E3014, 0xB8D2486D, 0xC79A1749, 0x9A1D7745,
			0x8766BB54, 0x1E04A7F7, 0x3D3DFF8A, 0xD5EC6BF4, 0xDBEF7D9F, 0x36EC0EA3, 0x1FEB2E4F, 0x15CFCC5C,
			0xD8C423FB, 0xD0EF3CC9, 0xEB244925, 0xBA5590C8, 0xA5F48AC4, 0x33C5321C, 0x613B67B2, 0x479C3A22,
			0xE21339CC, 0x10D210AA, 0x931DD7E2, 0xEF05EE06, 0xB82F2703, 0xA385CB2C, 0x5D67133C, 0x877EB7B4,
			0x1E3437F7, 0x5AFB43AE, 0x53C078F3, 0x94D90481, 0x1D964589, 0x08063A85, 0xE1322228, 0x1956B1E5,
			0x31860F13, 0x2E7B022F, 0x21182CA3, 0x96F703AC, 0x46819E2E, 0x0D28FE52, 0x3724D4DC, 0xA0EABE6B,
			0xC66699FD, 0xC6112FDD, 0x19C1E69C, 0x04D3658A, 0x4B55DD99, 0x31907D62, 0xF854B522, 0x4D678F26,
			0x22AE0582, 0xEAFED133, 0xE4A51D21, 0x84BD6DD6, 0xC1A51375, 0x3F28EE63, 0xFB737B1A, 0x70A1660E,
			0x8A8DFAA3, 0x1BE79937, 0xF7476978, 0x513C1764, 0x531AC6BF, 0x12C06908, 0x001CDB95, 0x1A4B6A53,
			0xD067FCE5, 0x12B2CFB6, 0x9DDB477F, 0x740E0066, 0x39DDF25A, 0xCC8BFA2D, 0xF1B20EAF, 0x64F2632C,
			0x9783CDEE, 0x63BFD4D8, 0x0084CFE5, 0x75F4E9E2, 0x19B48FD0, 0x6C48DDD8, 0x7A36AF93, 0x71865C4C,
			0x9CE0199D, 0x867027D7, 0x2CB7B77F, 0x84EF01DA, 0x72F5972F, 0x040F7074, 0xDF9AFA29, 0xC921F94E,
			0x75C08A36, 0x18C1EF9A, 0xD649A428, 0xC5B71937, 0x8A30738A, 0xD97CD348, 0x858129A6, 0x239E3B0A,
			0xBBB8ABC4, 0x80FAC4C2, 0xECFCF20B, 0xD9D711F9, 0xE2A4EF71, 0xB5FE87C0, 0xBE8B06B2, 0xAAFEF5A7,
			0x9C15DB3B, 0x0AEB8165, 0x4389A84A, 0x253B1D7A, 0x19047C79, 0x7CDC78A2, 0xD20ADF03, 0x56F55A71,
			0x3E730FA8, 0xFD8650D8, 0x959E234E, 0xB7546681, 0xDAD1B22A, 0x142A6E85, 0x8EF4BCE6, 0x68235B9D,
			0x85A13F85, 0x74096AE7, 0xA949BEA2, 0x29322D0D, 0xD5683858, 0x82846526, 0x403DAE08, 0x6DD1943A,
			0xE1279BFF, 0x9E7E4F04, 0x1C3A4524, 0x484525E4, 0x81D4CC5F, 0xE24124C0, 0x037464C0, 0xBF1BD691,
			0x26CEB003, 0x275EAD3A, 0xC5BDE908, 0x26414FF3, 0xA30519AD, 0xD7B43ABE, 0x2CE5D3D5, 0x88412761,
			0x97CA2070, 0xE5FBB9C7, 0x276DF0B4, 0x308F751F, 0x37A97DF6, 0xC9CD808C, 0xFE4CB380, 0x3D469303,
			0xAEE19096, 0xC0D5D42A, 0x4E823AD3, 0xF5F9CC3B, 0x4286619C, 0x9CA45E1C, 0x66C97340, 0x891AEC49,
			0x45BAE606, 0xC798F047, 0x52649D6C, 0xCE86FDFC, 0x80C6E402, 0xD6EC2F2B, 0x27C82282, 0x1FE26CE0,
			0x92F57EA7, 0xDE462F4D, 0x07497CAE, 0x5A48755C, 0x721502DD, 0x6CBE7935, 0x836D8003, 0x9EAD7F70,
			0x9AB3A42F, 0x4C8652D6, 0x32E39273, 0xE8FA3860, 0x1DA4F25A, 0x0CD6EF81, 0x02503F7D, 0x8854A0A1,
			0x9A30C4E8, 0x88157153, 0x05EFE294, 0x57C4C925, 0x2887D96F, 0xC1A71E3C, 0xE9F84163, 0x2D0985DE,
			0xD21E796C, 0x6FB5CE56, 0x02614ABF, 0xC3C7BE2C, 0xB54FED6F, 0xA617A083, 0xC3142D8F, 0x6079E4CE,
			0xCEFFC147, 0x1D0CB81B, 0xDC153E5F, 0xE36EF5BB, 0xD531161A, 0x165B1015, 0x7AA114ED, 0x3F7579B3,
			0xF7F395F1, 0xBC6172C7, 0xA86F875E, 0x0E6C51B3, 0xCDFEC2AF, 0x73C0E762, 0x824C2009, 0xC5A87748,
			0x94D40125, 0x8ABA3FFB, 0xD32BE060, 0x8C17EFF0, 0x21E2547E, 0x07CFFAD9, 0x05340E15, 0xF3310C92,
			0x9D8D1908, 0x86BA527F, 0xF943F672, 0xEF73FBF0, 0x46D95CA5, 0xC54CD95B, 0x9D855E89, 0x4BB5AF29
		};

		ls_nword_t i, j;
		uint_fast16_t vi;
		for (i = vi = 0; i < 2; ++i) {
			for (j = 0; j < LS_CRYPTO_PRNG_ISAAC_SIZE; ++j) {
				if (ctx.rsl[j] != vectors[vi++]) {
					result = LS_RESULT_ERROR(LS_RESULT_CODE_EARLY_EXIT);
					goto __cleanup;
				}
			}
			if (!ls_isaac_update(&ctx).success) {
				result = LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_FUNCTION, 1);
				goto __cleanup;
			}
		}
	} else {
		result = LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_FUNCTION, 2);
	}

__cleanup:
	if (!ls_isaac_clear(&ctx).success) {
		return LS_RESULT_ERROR_PARAM(LS_RESULT_CODE_FUNCTION, 3);
	}

	return result;
}
#endif
