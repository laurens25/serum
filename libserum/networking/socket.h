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

#ifndef __LS_NETWORKING_SOCKET_H
#define __LS_NETWORKING_SOCKET_H


#include "../core/stdincl.h"

#if (LS_WINDOWS)
#	include <WinSock2.h>
#	include <WS2tcpip.h>
#else
#	include <sys/types.h>
#	include <sys/socket.h>
#endif


#define LS_INVALID_SOCKET					(((uint32_t)0)-1)
#define LS_RESULT_CHECK_SOCKFD(fd, param)	LS_RESULT_CHECK((fd) == LS_INVALID_SOCKET, LS_RESULT_CODE_DESCRIPTOR, (param))


#define LS_SOCKET_EXITED					BIT_1	// Read-only, TODO
#define LS_SOCKET_ACCEPTED					BIT_2	// Read-only, TODO
#define LS_SOCKET_REFUSED					BIT_3	// Read-only, TODO
#define LS_SOCKET_SERVER					BIT_4

#define LS_SOCKET_REUSEADDR					BIT_5	// TODO
#define LS_SOCKET_REUSEPORT					BIT_6	// TODO
#define LS_SOCKET_REUSE						(LS_SOCKET_REUSEADDR | LS_SOCKET_REUSEPORT)

#define LS_SOCKET_ASYNC						BIT_7	// TODO
#define LS_SOCKET_ASYNC_CHILDREN			BIT_8	// TODO

#define LS_SOCKET_TIMEOUT_R					BIT_9
#define LS_SOCKET_TIMEOUT_W					BIT_10

#define LS_SOCKET_UDP						BIT_11

#define LS_SOCKET_CRYPTO					BIT_12	// TODO

#define LS_SOCKET_END_READ					BIT_13
#define LS_SOCKET_END_WRITE					BIT_14


typedef uintptr_t ls_sockfd_t;
typedef struct ls_socket {
	struct addrinfo *addrinfo;
	struct addrinfo *selected;
	ls_sockfd_t fd;
	uint32_t flags;
	uint32_t mtu;
} ls_socket_t;


enum ls_socket_option_type {
	LS_SO_NONE = 0,
	LS_SO_ASYNC = 1,
	// TODO: LS_SO_CRYPTO = 2,
	LS_SO_TIMEOUT_R = 4,
	LS_SO_TIMEOUT_W = 8,
	LS_SO_TIMEOUT_RW = (LS_SO_TIMEOUT_R | LS_SO_TIMEOUT_W)
};


#ifdef __cplusplus
extern "C" {
#endif

	LSAPI ls_result_t ls_socket_init_ex(ls_socket_t *const LS_RESTRICT ctx, const char *LS_RESTRICT node, const uint32_t flags);
	LSAPI ls_result_t ls_socket_init(ls_socket_t *const LS_RESTRICT ctx, const char *LS_RESTRICT node);
	LSAPI ls_result_t ls_socket_clear(ls_socket_t *const ctx);

	LSAPI ls_result_t ls_socket_start(ls_socket_t *const ctx, const uint16_t port);
	LSAPI ls_result_t ls_socket_stop_ex(ls_socket_t *const ctx, const ls_bool force, const uint_fast16_t timeout);
	LSAPI ls_result_t ls_socket_stop(ls_socket_t *const ctx, const ls_bool force);

	LSAPI ls_result_t ls_socket_fromfd(ls_socket_t *const ctx, const ls_sockfd_t fd, const uint32_t flags);

	LSAPI ls_sockfd_t ls_socket_acceptfd(const ls_socket_t *const LS_RESTRICT ctx, struct sockaddr *const LS_RESTRICT saddr, socklen_t *const LS_RESTRICT saddrlen);
	LSAPI ls_result_t ls_socket_accept(ls_socket_t *const LS_RESTRICT out, const ls_socket_t *const LS_RESTRICT ctx, struct sockaddr *const LS_RESTRICT saddr, socklen_t *const LS_RESTRICT saddrlen);

	LSAPI ls_result_t ls_socket_write(size_t *const LS_RESTRICT out_size, const ls_socket_t *const LS_RESTRICT ctx, const void *const LS_RESTRICT in, size_t size);
	LSAPI ls_result_t ls_socket_write_str(size_t *const LS_RESTRICT out, const ls_socket_t *const LS_RESTRICT ctx, const char *const LS_RESTRICT str);

	LSAPI ls_result_t ls_socket_read(size_t *const LS_RESTRICT out_size, const ls_socket_t *const LS_RESTRICT ctx, void *const LS_RESTRICT out, const size_t size);

	LSAPI ls_result_t ls_socket_set_option(ls_socket_t *const ctx, const enum ls_socket_option_type type, const uint32_t value);

#ifdef __cplusplus
}
#endif


#endif
