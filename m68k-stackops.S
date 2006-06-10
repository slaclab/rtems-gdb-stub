#include <rtems/asm.h>
#include "rtems-gdb-stub-m68k.h"

/* wrapper for exception handler to save d2..d7, a2..a6 */

/* we save d0..a6 so we match the struct _M68k_Exception_Frame layout;
 * note that d0/d1, a0/a1 and a7 are clobbered and must be re-calculated
 * (done in C-code).
 */
	.align 4
	.global SYM(_m68k_gdb_exception_wrapper)
	.global SYM(_m68k_gdb_exception_handler)
	.global SYM(hdl)
SYM(_m68k_gdb_exception_wrapper):
	lea a7@(-M68K_FRAME_SIZE),a7
	movml  d0-d7/a0-a6,a7@      | save regs; d0,d1,a0,a1 are possibly invalid
	jsr	SYM(_m68k_gdb_exception_handler)
	movml  a7@, d0-d7/a0-a6
	lea     a7@(M68K_FRAME_SIZE),a7
	rts

	.align 4
	.global SYM(_m68k_gdb_frame_cleanup)
	.global SYM(_fdebug)
SYM(_m68k_gdb_frame_cleanup):
	jsr SYM(_fdebug)
	lea	a7@(2),a7           | skip size field
	movml  a7@,d0-d7/a0-a7      | restore regs;
	rte                         | restore PS, PC
