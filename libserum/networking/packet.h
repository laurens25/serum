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

#ifndef __LS_NETWORKING_PACKET_H
#define __LS_NETWORKING_PACKET_H


#include "../core/stdincl.h"

#define LS_PACKET_PAYLOAD					BIT_1


typedef struct ls_packet_header {
	void *value;
	uint8_t size;
} ls_packet_header_t;

typedef struct ls_packet {
	ls_packet_header_t *headers;
	void *payload;
	uint32_t payload_size;
	uint8_t command			: 4;
	uint8_t header_count	: 4;
	uint8_t flags;
	uint8_t __h_alloc_sz;
} ls_packet_t;


#ifdef __cplusplus
extern "C" {
#endif

	LSAPI ls_result_t ls_packet_init(ls_packet_t *packet, uint8_t command, uint8_t flags);
	LSAPI ls_result_t ls_packet_clear_ex(ls_packet_t *packet, ls_bool free_headers, ls_bool free_payload);
	LSAPI ls_result_t ls_packet_clear(ls_packet_t *packet);
	LSAPI ls_result_t ls_packet_add_header(ls_packet_t *packet, uint8_t size, void *value);
	LSAPI ls_result_t ls_packet_set_payload(ls_packet_t *packet, uint32_t size, void *value);
	LSAPI void* ls_packet_encode(ls_packet_t *packet, size_t *const out_size);

#ifdef __cplusplus
}
#endif


#endif
