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
**    Template file, used by sha2-template.c
**
*/


#ifdef SHA2_UPDATE
ls_result_t
SHA2_UPDATE(SHA2_CTX *ctx, SHA2_NATIVE_TYPE block[16]) {
	LS_RESULT_CHECK_NULL(ctx, 1);
	LS_RESULT_CHECK_NULL(block, 2);

	register SHA2_NATIVE_TYPE
		a = ctx->h[0],
		b = ctx->h[1],
		c = ctx->h[2],
		d = ctx->h[3],
		e = ctx->h[4],
		f = ctx->h[5],
		g = ctx->h[6],
		h = ctx->h[7],
		s0, s1, ch, temp1, temp2, maj;

	SHA2_NATIVE_TYPE w[SHA2_WR];

	register uint_fast16_t i;

	for (i = 16; i--;) {
		w[i] = block[i];
	}

	for (i = 16; i < SHA2_WR; ++i) {
		s0 = (SHA2_ROTR(w[(i - 15)], SHA2_ROTR_1) ^ SHA2_ROTR(w[(i - 15)], SHA2_ROTR_2) ^ (w[(i - 15)] >> SHA2_SHR_1));
		s1 = (SHA2_ROTR(w[(i -  2)], SHA2_ROTR_3) ^ SHA2_ROTR(w[(i -  2)], SHA2_ROTR_4) ^ (w[(i -  2)] >> SHA2_SHR_2));
		w[i] = (w[(i - 16)] + s0 + w[(i - 7)] + s1);
	}

	for (i = 0; i < SHA2_WR; ++i) {
		s1 = (SHA2_ROTR(e, SHA2_ROTR_5) ^ SHA2_ROTR(e, SHA2_ROTR_6) ^ SHA2_ROTR(e, SHA2_ROTR_7));
		ch = ((e & f) ^ (~(e)& g));
		temp1 = (h + s1 + ch + SHA2_CONSTANTS[i] + w[i]);
		s0 = (SHA2_ROTR(a, SHA2_ROTR_8) ^ SHA2_ROTR(a, SHA2_ROTR_9) ^ SHA2_ROTR(a, SHA2_ROTR_10));
		maj = ((a & b) ^ (a & c) ^ (b & c));
		temp2 = (s0 + maj);

		h = g;
		g = f;
		f = e;
		e = (d + temp1);
		d = c;
		c = b;
		b = a;
		a = (temp1 + temp2);
   }

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;

	return LS_RESULT_SUCCESS;
}
#endif