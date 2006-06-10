/* $Id$ */
/* Target BSP specific gdb stub helpers for m68k */
#ifndef RTEMS_GDB_STUB_M68K_H
#define RTEMS_GDB_STUB_M68K_H

#include <rtems/score/cpu.h>

#ifndef ASM

typedef struct _M68k_GdbFrameRec * RtemsDebugFrame;

#include "rtems-gdb-stubP.h"


/* Register layout in GDB layout (no FP yet) */

typedef struct _M68k_RegsRec {
	uint32_t	d[8];
	uint32_t	a[8];
	uint16_t	ps;	/* status        */
	uint16_t	fvo;	/* format/vector */
	uint32_t	pc;
} M68k_RegsRec, *M68k_Regs;

/* Layout of the stuff we dump on the user stack to communicate with
 * the daemon
 */
typedef struct _M68k_GdbFrameRec {
	uint16_t		size;	/* to help assembly code popping this stuff */
	/* message header */
	RtemsDebugMsgRec	msg;
	/* registers */
	M68k_RegsRec		regs;
	/* vector    */
	uint32_t                vector;
} M68k_GdbFrameRec, *M68k_GdbFrame;

/* Layout on the interrupt stack */
typedef struct _M68k_Exception_Frame {
	M68k_RegsRec    regs;
	/* return addr to _ISR_Handler; this and everything beyond
         * was pushed by _ISR_Handler
         */
	uint32_t	rtn_addr_leave_alone;
	uint32_t	vector;
	uint32_t	*usr_stack;           /* user stack where we retrieve some values */
} M68k_ExceptionFrameRec, *M68k_ExceptionFrame;
#endif

/* this is for the assembler; it MUST match the frame rec size
 * MINUS everything already on the stack!
 */
#define M68K_FRAME_SIZE     ((8+8+2)*4)

/* 8*d, 8*a, ps, pc */
#define NUMREGBYTES ((8+8+1+1)*4)

#ifndef ASM

typedef enum {
  M68K_D0_REGNUM = 0,
  M68K_D1_REGNUM = 1,
  M68K_D2_REGNUM = 2,
  M68K_D3_REGNUM = 3,
  M68K_D4_REGNUM = 4,
  M68K_D5_REGNUM = 5,
  M68K_D6_REGNUM = 6,
  M68K_D7_REGNUM = 7,
  M68K_A0_REGNUM = 8,
  M68K_A1_REGNUM = 9,
  M68K_A2_REGNUM = 10,
  M68K_A3_REGNUM = 11,
  M68K_A4_REGNUM = 12,
  M68K_A5_REGNUM = 13,
  M68K_FP_REGNUM = 14,      /* Address of executing stack frame.  */
  M68K_SP_REGNUM = 15,      /* Address of top of stack.  */
  M68K_PS_REGNUM = 16,      /* Processor status. */
  M68K_PC_REGNUM = 17,      /* Program counter.  */
  M68K_FP0_REGNUM = 18,     /* Floating point register 0.  */
  M68K_FPC_REGNUM = 26,     /* 68881 control register.  */
  M68K_FPS_REGNUM = 27,     /* 68881 status register.   */
  M68K_FPI_REGNUM = 28
} M68k_Regnum;


static inline void BREAKPOINT()
{
	asm volatile("trap #0");
}


/* GDB-6.3 / m68k has no frame_align method and doesn't honour
 * the red-zone :-(
 * Therefore, we must resort to a separate stack.
 * See 'switch_stack.c' for an explanation how it works...
 */
#define USE_GDB_REDZONE

/* Define architecture specific stuff for i386 */

typedef struct FrameRec_ {
	struct FrameRec_ *up;
} FrameRec, *Frame;

#define STACK_ALIGNMENT 16 /* ?? */
#define FRAME_SZ        ((128+18*4+500)>>2)
#define SP_GET(sp)	do { asm volatile("movl %%a7, %0":"=r"(sp)); } while(0)
#define BP_GET(bp)	do { asm volatile("movl %%a6, %0":"=r"(bp)); } while(0)
#define FLIP_REGS(diff) do { asm volatile("addl %0, %%a6; addl %0, %%a7"::"r"(diff)); } while(0)
#define SP(f)       ((unsigned long)(f)->a[7])
#define PC(f)       ((unsigned long)(f)->pc)

#endif /* ASM */

#endif
