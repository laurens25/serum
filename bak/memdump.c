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

#define FILE_PATH								"debug/memdump.c"

#include "./memdump.h"
#include "./log.h"

#include <stdio.h>
#include <inttypes.h>


ID("memory dumping");


#if (LS_ARCH_BITS == 32)
#	define PTRFMT								"0x%08"PRIXPTR
#else
#	define PTRFMT								"0x%016"PRIXPTR
#endif


void
ls_memdump_ex(const void *const ptr, const size_t size, int columns, int items_per_column) {
	if (!ptr || !size) {
		return;
	}

	if (columns < 1) {
		columns = 1;
	}

	if (items_per_column < 1) {
		items_per_column = 1;
	}


	const uint8_t *p8 = ptr;
	printf(PTRFMT": ", ((uintptr_t)p8));

	int c = 0, ic = 0;
	size_t i;
	if (items_per_column == 1) {
		for (i = 0; i < size; ++i) {
			printf("%02X ", *(p8++));
			if (++c >= columns) {
				c = 0;
				if (i != (size - 1)) {
					printf("\n"PTRFMT": ", ((uintptr_t)p8));
				} else {
					puts("");
				}
			}
		}
	} else {
		for (i = 0; i < size; ++i) {
			printf("%02X", *(p8++));
			if (++ic >= items_per_column) {
				ic = 0;
				if (++c >= columns) {
					c = 0;
					if (i != (size - 1)) {
						printf("\n"PTRFMT": ", ((uintptr_t)p8));
					} else {
						puts("");
					}
				} else {
					fputs(" ", stdout);
				}
			}
		}
	}
	if (c > 0) {
		puts("");
	}
}


void
ls_memdump(const void *const ptr, const size_t size) {
	ls_memdump_ex(ptr, size, 16, 1);
}


void
ls_vmemdump_ex(const void *const LS_RESTRICT ptr, const size_t size, int columns, int items_per_column, const char *const LS_RESTRICT str) {
	if (!ptr || !size) {
		return;
	}

	if (str) {
		puts(str);
	}

	ls_memdump_ex(ptr, size, columns, items_per_column);

	if (str) {
		puts("");
	}
}


void
ls_vmemdump(const void *const LS_RESTRICT ptr, const size_t size, const char *const LS_RESTRICT str) {
	ls_vmemdump_ex(ptr, size, 16, 1, str);
}


void
ls_memdiff_ex(const void *const LS_RESTRICT cmp1, const void *const LS_RESTRICT cmp2, const size_t size, int columns) {
	if (!cmp1 || !cmp2 || !size) {
		return;
	}

	if (columns < 1) {
		columns = 1;
	}

#define DIFF_LEFT							LS_ANSI_ESCAPE LS_ANSI_FG_BLACK LS_ANSI_OPT LS_ANSI_BG_GREEN LS_ANSI_OPT LS_ANSI_UNDERLINE LS_ANSI_OPT LS_ANSI_BLINK LS_ANSI_TERMINATE
#define DIFF_RIGHT							LS_ANSI_ESCAPE LS_ANSI_FG_WHITE LS_ANSI_OPT LS_ANSI_BG_RED LS_ANSI_OPT LS_ANSI_BRIGHT LS_ANSI_OPT LS_ANSI_UNDERLINE LS_ANSI_OPT LS_ANSI_BLINK LS_ANSI_TERMINATE

	const uint8_t
		*p8_m = cmp1,
		*p8_s = cmp2;
	uint8_t m8, s8;

	printf(PTRFMT"/"PTRFMT": ", ((uintptr_t)p8_m), ((uintptr_t)p8_s));

	unsigned int c = 0;
	size_t i;
	for (i = 0; i < size; ++i) {
		if ((m8 = *(p8_m++)) == (s8 = *(p8_s++))) {
			printf(" %02X  ", m8);
		} else {
			printf(DIFF_LEFT "%02X" DIFF_RIGHT "%02X" LS_ANSI_RESET " ", m8, s8);
		}
		if (++c >= columns) {
			c = 0;
			if (i != (size - 1)) {
				printf("\n"PTRFMT"/"PTRFMT": ", ((uintptr_t)p8_m), ((uintptr_t)p8_s));
			} else {
				puts("");
			}
		}
	}
	if (c > 0) {
		puts("");
	}
}


void
ls_memdiff(const void *const LS_RESTRICT cmp1, const void *const LS_RESTRICT cmp2, const size_t size) {
	ls_memdiff_ex(cmp1, cmp2, size, 16);
}