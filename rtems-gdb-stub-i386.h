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

/* GDB-6.2.1 / i386 has no frame_align method and doesn't honour
 * the red-zone :-(
 * Therefore, we must resort to a separate stack.
 * See 'switch_stack.c' for an explanation how it works...
 */
#undef USE_GDB_REDZONE

/* Define architecture specific stuff for i386 */

typedef struct FrameRec_ {
	struct FrameRec_ *up;
} FrameRec, *Frame;

#define STACK_ALIGNMENT 16 /* ?? */
#define FRAME_SZ        ((128+16*4+500)>>2)
#define SP_GET(sp)	do { asm volatile("movl %%esp, %0":"=r"(sp)); } while(0)
#define BP_GET(bp)	do { asm volatile("movl %%ebp, %0":"=r"(bp)); } while(0)
#define FLIP_REGS(diff) do { asm volatile("add %0, %%esp; add %0, %%ebp"::"r"(diff)); } while(0)
#define SP(f)       ((unsigned long)(f)->esp0 + 5*4)
#define PC(f)       ((unsigned long)(f)->eip)


#endif
