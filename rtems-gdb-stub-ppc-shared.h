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

#include "rtems-gdb-stubP.h"

#define USE_GDB_REDZONE

#ifndef USE_GDB_REDZONE
/* see switch_stack.c for more explanations */

/* SP and BP are the same thing on PPC */
#define SP_GET(sp)  do { asm volatile ("mr %0,1":"=r"(sp)); } while(0)
#define BP_GET(bp)  do { asm volatile ("mr %0,1":"=r"(bp)); } while(0)
#define FLIP_REGS(diff) do { asm volatile("add 1, 1, %0"::"r"(diff)); } while (0)
#define FRAME_SZ   (((EXCEPTION_FRAME_END+1200+15)&~15)>>2)
/* EABI alignment req */
#define STACK_ALIGNMENT 16
#define SP(f)		((unsigned long)(f)->GPR1)
#define PC(f)		((unsigned long)(f)->EXC_SRR0)
#endif


/* Frame is needed by 'switch_stack.c' but also by the ppc
 * specific code - hence it is outside of the REDZONE ifdef
 */
typedef struct FrameRec_ {
	struct FrameRec_ *up;
	unsigned 		  lr;
} FrameRec, *Frame;

#endif
