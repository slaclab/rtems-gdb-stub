/* $Id$ */
/* Target BSP specific gdb stub helpers for powerpc/shared & derived */
#ifndef RTEMS_GDB_STUB_SHARED_PPC_H
#define RTEMS_GDB_STUB_SHARED_PPC_H

#include <bsp/vectors.h>

/* braindead definition; BSP_Exception_frame is NOT quite
 * identical with CPU_Interrupt_frame for new exception processing;
 * why???
 */
typedef BSP_Exception_frame *RtemsDebugFrame;

/* 32 GPRs, 32 FPRs, PC, PS (msr??), CR, LR, CTR, XER, FPSCR */
#define NUMREGBYTES (32*4+32*8+2*4+5*4)


static inline void BREAKPOINT()
{
	asm volatile("sc");
}

#include "rtems-gdb-stub.h"

#endif
