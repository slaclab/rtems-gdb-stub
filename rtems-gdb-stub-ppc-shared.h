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


void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugFrame f, rtems_id tid);

void
rtems_gdb_tgt_r2f(RtemsDebugFrame f, rtems_id tid, unsigned char *buf);

static inline void BREAKPOINT()
{
	asm volatile("sc");
}

extern rtems_id rtems_gdb_q;

/* install / uninstall exception handler */
int
rtems_debug_install_ehandler(int action);
#endif
