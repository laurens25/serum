/*******************************************************************************
 * *                                                                            **
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

#ifndef __LS_CRYPTO_SYMMETRIC__SIGNATURES_H
#define __LS_CRYPTO_SYMMETRIC__SIGNATURES_H


#include "../../core/stdincl.h"


typedef ls_result_t (*ls_sym_init_func_t)(void *const LS_RESTRICT ctx, const void *const LS_RESTRICT key, const size_t key_size);
typedef ls_result_t (*ls_sym_clear_func_t)(void *const ctx);
typedef ls_result_t (*ls_sym_encrypt_block_func_t)(const void *const LS_RESTRICT ctx, void *const LS_RESTRICT block);
typedef ls_sym_encrypt_block_func_t ls_sym_decrypt_block_func_t;


#endif
