/* $Id$ */
/* Target BSP specific gdb stub helpers for powerpc/shared & derived */
#ifndef RTEMS_GDB_STUB_I386_H
#define RTEMS_GDB_STUB_I386_H

#include <rtems/score/cpu.h>

/* braindead definition; BSP_Exception_frame is NOT quite
 * identical with CPU_Interrupt_frame for new exception processing;
 * why???
 */
typedef CPU_Exception_frame *RtemsDebugFrame;

/* 16 GPRs, 8 FPRs, 8 FPCRs */
#define NUMREGBYTES (16*4+8*8+8*4)

static inline void BREAKPOINT()
{
	asm volatile("int3");
}

#include "rtems-gdb-stub.h"

#endif
