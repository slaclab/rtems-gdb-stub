/* $Id$ */
/* Target BSP specific gdb stub helpers for powerpc/shared & derived */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/bspIo.h> /* printk */
#include <bsp.h>

#include "rtems-gdb-stub-ppc-shared.h"

#include <libcpu/raw_exception.h> 
#include <libcpu/spr.h> 

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

typedef struct FrameRec_ {
	struct FrameRec_ *up;
	unsigned 		  lr;
} FrameRec, *Frame;

static Thread_Control *
get_tcb(rtems_id tid)
{
Objects_Locations	loc;
Thread_Control		*tcb = 0;

	if ( !tid )
		return 0;

	tcb = _Thread_Get(tid, &loc);

    if (OBJECTS_LOCAL!=loc || !tcb) {
		if (tcb)
			_Thread_Enable_dispatch();
        fprintf(stderr,"Id %x not found on local node\n",tid);
    }
	return tcb;
}

/* max number of simultaneously stopped threads */
#define NUM_FRAMES	40

#define FRAME_SZ (((EXCEPTION_FRAME_END+1200+15)&~15)>>2)


typedef union GdbStackFrameU_ *GdbStackFrame;

typedef union GdbStackFrameU_ {
	struct {
		unsigned long frame[FRAME_SZ];
		unsigned long lrroom[4];
	} stack;
	GdbStackFrame next;
} GdbStackFrameU
/* EABI alignment req */
__attribute__((aligned(16)));

static GdbStackFrameU savedStack[NUM_FRAMES] = {{{{0}}}};
static GdbStackFrame freeList = 0;

#define GPR0_OFF  (0)
#define FPR0_OFF  (32*4)
#define PC___OFF  (32*4+32*8+4*0)
#define PS___OFF  (32*4+32*8+4*1)
#define CR___OFF  (32*4+32*8+4*2)
#define LR___OFF  (32*4+32*8+4*3)
#define CTR__OFF  (32*4+32*8+4*4)
#define XER__OFF  (32*4+32*8+4*6)
#define FPSCR_OFF (32*4+32*8+4*7)

typedef struct BpntRec_ *Bpnt;

typedef struct BpntRec_ {
	volatile unsigned long *addr;
	unsigned long opcode;
} BpntRec;

#define NUM_BPNTS 32

static BpntRec bpnts[NUM_BPNTS] = {{0}};

#define TRAP(no) (0x0ce00000 + ((no)&0xffff)) /* twi 7,0,no */
#define TRAPNO(opcode) ((int)(((opcode) & 0xffff0000) == TRAP(0) ? (opcode)&0xffff : -1))

static inline unsigned long
do_patch(volatile unsigned long *addr, unsigned long val)
{
unsigned long rval;

	rval = *addr;
	/* longjmp should restore MSR */
	/* disable interrupts AND MMU to work around write-protection */
	asm volatile(
		"	mfmsr 0         \n"
		"   andc  7,0,%0    \n" 
		"	mtmsr 7         \n" /* msr is exec. synchronizing; rval access complete */
		"	isync           \n" /* context sync.; DR off after this                 */
		"   stw   %2,0(%1)  \n"
		"	dcbst 0,%1      \n" /* write out data cache line (addr)                 */
		"	icbi  0,%1      \n" /* invalidate instr. cache line (addr)              */
		"	mtmsr 0			\n" /* msr is exec. synchr.; mem access completed       */
		"   sync            \n" /* probably not necessary                           */
		"	isync           \n" /* context sync.; MMU on after this                 */
		::"r"(MSR_EE|MSR_DR), "b"(addr), "r"(val)
		:"r0","r7");
	return rval;
}


int
rtems_gdb_tgt_regoff(int regno, int *poff)
{
*poff = 0;
	if ( regno < 0 || regno > 70 )
		return -1;
	if ( regno < 32 ) {
		*poff += regno*4;
		return 4;
	}
	*poff += 32*4;
	regno -= 32;
	if ( regno < 32 ) {
		*poff += regno*8;
		return 8;
	}
	regno -= 32;
	*poff += 32*8 + regno*4;
	return 4;
}

/* map exception frame into register array (GDB layout) */
void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugMsg msg)
{
Thread_Control *tcb;
RtemsDebugFrame f = msg->frm;
int            deadbeef = 0xdeadbeef, i;

	memset(buf, 0, NUMREGBYTES);

	if ( f ) {
		memcpy(buf + GPR0_OFF, &f->GPR0, 32*4);
		memcpy(buf + PC___OFF, &f->EXC_SRR0, 4);
		memcpy(buf + PS___OFF, &f->EXC_SRR1, 4);
		memcpy(buf + CR___OFF, &f->EXC_CR,   4);
		memcpy(buf + LR___OFF, &f->EXC_LR,   4);
		memcpy(buf + CTR__OFF, &f->EXC_CTR,  4);
		memcpy(buf + XER__OFF, &f->EXC_XER,  4);
	} else {
		memcpy(buf + GPR0_OFF, &deadbeef, 4);
		for ( i = 3*4; i < 13*4; i+=4 )
			memcpy(buf + (GPR0_OFF + i), &deadbeef, 4);
		memcpy(buf + XER__OFF, &deadbeef, 4);
		memcpy(buf + CTR__OFF, &deadbeef, 4);
	}

	if ( (tcb = get_tcb(msg->tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			memcpy(buf + FPR0_OFF, &fpc->f[0], 32*8 );
			memcpy(buf + FPSCR_OFF, &fpc->fpscr, 4);
		}
		if (!f) {
			Frame        sfr = (Frame)tcb->Registers.gpr1;
			unsigned pcdummy = tcb->Registers.pc - 4;
			if (!sfr->lr)
				sfr = sfr->up;
			/* dummy up from the TCB */
			memcpy(buf + GPR0_OFF+4,    &tcb->Registers.gpr1,       2 *4);
			memcpy(buf + GPR0_OFF+4*13, &tcb->Registers.gpr13, (32-13)*4);
			memcpy(buf + LR___OFF,      &sfr->lr,                      4);
			memcpy(buf + CR___OFF,      &tcb->Registers.cr,            4);
			memcpy(buf + PC___OFF,      &pcdummy,                      4);
			memcpy(buf + PS___OFF,      &tcb->Registers.msr,           4);
		}
		_Thread_Enable_dispatch();
	}
}

void
rtems_gdb_tgt_r2f(RtemsDebugMsg msg, unsigned char *buf)
{
RtemsDebugFrame f = msg->frm;
Thread_Control *tcb = 0;

	if ( f ) {
		memcpy(&f->GPR0,     buf + GPR0_OFF, 32*4);
		memcpy(&f->EXC_SRR0, buf + PC___OFF, 4);
		memcpy(&f->EXC_SRR1, buf + PS___OFF, 4);
		memcpy(&f->EXC_CR,   buf + CR___OFF, 4);
		memcpy(&f->EXC_LR,   buf + LR___OFF, 4);
		memcpy(&f->EXC_CTR,  buf + CTR__OFF, 4);
		memcpy(&f->EXC_XER,  buf + XER__OFF, 4);
	}

	if ( msg->tid && (tcb = get_tcb(msg->tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			memcpy(&fpc->f[0],   buf+FPR0_OFF,    32*8 );
			memset(&fpc->fpscr,  0,               sizeof(fpc->fpscr));
			memcpy(&fpc->fpscr,  buf + FPSCR_OFF, 4);
		}
		if ( !f ) {
			/* setup TCB */
			memcpy(&tcb->Registers.gpr1,  buf + (GPR0_OFF + 4),         2 *4);
			memcpy(&tcb->Registers.gpr13, buf + (GPR0_OFF + 4*13), (32-13)*4);
/*			memcpy(&((Frame)tcb->Registers.gpr1)->lr, buf + LR___OFF, 4);       */
			memcpy(&tcb->Registers.pc,    buf + PC___OFF, 4);
			memcpy(&tcb->Registers.msr,   buf + PS___OFF, 4);
			memcpy(&tcb->Registers.cr,    buf + CR___OFF, 4);
		}
		_Thread_Enable_dispatch();
	}

}

static void (*origHandler)()=0;

#define RELOC(ptr) ((void*)((diff)+(unsigned long)(ptr)))

static void
exception_handler(BSP_Exception_frame *f)
{
static struct {
	int 			trapno;
	unsigned long	msr;
	int				sig;
} stepOverState = { -1,0,0 };
RtemsDebugMsgRec msg;

    if (   rtems_interrupt_is_in_progress()
	    || !_Thread_Executing 
		|| (RTEMS_SUCCESSFUL!=rtems_task_ident(RTEMS_SELF,RTEMS_LOCAL, &msg.tid)) ) {
		/* unable to deal with this situation */
		origHandler(f);
		return;
	}
printk("Task %x got exception %i, frame %x, GPR1 %x, IP %x\n\n",
	msg.tid,f->_EXC_number, f, f->GPR1, f->EXC_SRR0);
printk("\n");

	/* the debugger should be able to handle its own exceptions */
	msg.frm = f;
    msg.sig = SIGHUP;

	switch ( f->_EXC_number ) {
		case ASM_MACH_VECTOR     :
			_BSP_clear_hostbridge_errors(1,0);
			msg.sig = SIGBUS;
		break;

		case ASM_PROT_VECTOR     :
		case ASM_ISI_VECTOR      :
		case ASM_ALIGN_VECTOR    :  
			msg.sig = SIGSEGV;
		break;

		case ASM_PROG_VECTOR     :
			/* did we run into a soft breakpoint ? */
			msg.sig = TRAPNO(*(volatile unsigned long*)f->EXC_SRR0) < 0 ? SIGILL : SIGTRAP;
		break;

		case ASM_FLOAT_VECTOR    :
			msg.sig = SIGFPE;
		break;

		case ASM_DEC_VECTOR      :  
			msg.sig = SIGALRM;
		break;

		case ASM_SYS_VECTOR      :
			msg.sig = SIGTRAP;
		break;

		case ASM_TRACE_VECTOR    :
			if ( stepOverState.sig ) {
				/* 'phase 2' of single stepping */
				/* we just stepped over a soft breakpoint;
			 	 * NO interrupts could happen (we disabled MSR_EE)
			 	 * we completely owned the CPU until now (therefore,
			 	 * a single static variable is OK to maintain our state
			 	 */
				if ( stepOverState.trapno >= 0 ) {
					/* restore soft bpnt */
					do_patch(bpnts[stepOverState.trapno].addr, TRAP(stepOverState.trapno));
				}

				/* restore MSR       */
				f->EXC_SRR1          = stepOverState.msr;

				/* restore continuation signal */
				msg.contSig = stepOverState.sig;

				/* important: mark stepping terminated */
				stepOverState.sig    = 0;

				if ( SIGCONT == msg.contSig ) {
					/* we are DONE and let the thread resume */
					return;
				}
			}
			/* in any case, we should switch SE off now.
			 * It is possible to end up here if they attach
			 * to a thread without breakpoint (step after
			 * task_switch_to())
			 */
			f->EXC_SRR1 &= ~MSR_SE;
			msg.sig = SIGTRAP;
		break;

		default: break;
	}
    if (f->EXC_SRR1 & MSR_FP) {
		/* thread dispatching is _not_ disabled at this point; hence
		 * we must make sure we have the FPU enabled...
		 * original MSR will be restored anyways.
		 */
		_write_MSR( _read_MSR() | MSR_FP );
		__asm__ __volatile__("isync");
	}
	if ( msg.tid == rtems_gdb_tid ) {
		f->EXC_SRR0 = (unsigned long)rtems_debug_handle_exception;
		f->GPR3     = msg.sig;
        return;
	} else {

		if ( ! rtems_gdb_break_tid || rtems_gdb_break_tid == msg.tid ) {
		
			rtems_debug_notify_and_suspend(&msg);
		} else {
			/* this thread ignores the breakpoint */
			msg.contSig = SIGCONT;
		}

		/* resuming; we might have to step over a breakpoint */
		if ( (stepOverState.trapno = TRAPNO(*(volatile unsigned long *)f->EXC_SRR0)) >= 0 ) {
			/* indeed; have to patch back and single step over it */
			do_patch(bpnts[stepOverState.trapno].addr, bpnts[stepOverState.trapno].opcode);
		}

		if ( stepOverState.trapno >= 0 || SIGCONT != msg.contSig ) {
			/* phase 1 of a single step */

			/* save the state we need after the step since 'msg'
			 * will have GONE (it's on the stack)
			 */
			stepOverState.msr = f->EXC_SRR1;
			stepOverState.sig = msg.contSig;

			/* DISABLE interrupts but enable TRACE exception      */
			/* this is IMPORTANT as it asserts that we own the CPU
			 * until this exception handler is called again.
			 * Logically, execution 'resumes' in the
			 * ASM_TRACE_VECTOR branch above
			 */
			f->EXC_SRR1 &= ~MSR_EE;
			f->EXC_SRR1 |= MSR_SE;
		} else {
			stepOverState.sig = 0;
		}
		return;
	}

	origHandler(f);
}

static void 
flip_stack(Frame top, long diff)
{
Frame fix;
Frame sp;

	asm volatile ("mr %0,1":"=r"(sp));

printk("OLD BOS %x -> %x\n",sp,  *(unsigned long*)sp);
printk("OLD TOS %x -> %x\n",top, *(unsigned long*)top);

	/* fixup the frame pointers */
	for (fix = sp; fix < top; ) {
		fix->up = RELOC(fix->up);
		fix = fix->up;
	}
	memcpy(RELOC(sp), sp, (unsigned)top - (unsigned)sp);
	/* switch to new stack */
	asm volatile("mr 1,%0"::"r"(RELOC(sp)):"memory");

/* DEBUG: purge the old region; make sure it works */
memset((void*)sp,0,(unsigned)top - (unsigned)sp);

printk("NEW BOS %x -> %x\n",RELOC(sp),*(unsigned long*)RELOC(sp));
printk("NEW TOS %x -> %x\n",RELOC(top),*(unsigned long*)RELOC(top));
}

static void
switch_stack(BSP_Exception_frame *f)
{
GdbStackFrame volatile stk;
unsigned long diff;

	/* Here comes creepy stuff:
	 * GDB expects us to leave the stack as 
	 * the interrupted function left it.
	 * However, the whole exception handler has
	 * been using the thread stack which conflicts
	 * with this GDB requirement. Hence, we
	 * save everything into a separate area and
	 * switch the stack pointer.
	 */

	/* allocate a frame */
	if ( !(stk=freeList) )
		rtems_fatal_error_occurred(RTEMS_NO_MEMORY);

	freeList  = freeList->next;
	stk->next = 0;

	/* fixup the exception frame pointer */
	/* copy frame; hopefully nobody upstream in the call stack
	 * uses other pointers into the frame...
	 */

	diff      =  (unsigned long)(stk->stack.frame+FRAME_SZ);
	diff     -=  (unsigned long)f->GPR1;

printk("OLD STK %x\n",stk);

	flip_stack((Frame)f->GPR1, diff);

printk("NEW STK %x\n",stk);


	f = RELOC(f);

	exception_handler(f);

	/* calculate diff again - GPR1 might have magically changed!!
	 * because gdb can push stuff on the stack (which is the main
	 * reason why we do the stack switching in the first place)
	 */
	diff      =  (unsigned long)f->GPR1;
	diff     -=  (unsigned long)(stk->stack.frame+FRAME_SZ);

	/* switch back */
	flip_stack((Frame)stk->stack.lrroom,diff);

f = RELOC(f);
printk("BACK resuming at PC %x SP %x\n",f->EXC_SRR0, f->GPR1);

	/* free up the frame -- this context runs until the
	 * frame is popped without interruption, hence adding
	 * it to the free list should be safe.
	 */

	stk->next = freeList;
	freeList  = stk;
}

#if 1
#define exception_handler switch_stack
#endif

int
rtems_debug_install_ehandler(int action)
{
int rval = 0;
rtems_unsigned32 flags;

	if ( action ) {
		/* initialize stack frame list */
		for ( freeList = savedStack + (NUM_FRAMES-1); freeList > savedStack; freeList-- )
			(freeList-1)->next = freeList;
	}

	rtems_interrupt_disable(flags);
	if ( action ) {
		/* install */
		if ( globalExceptHdl == exception_handler ) {
			rval = -1;
		} else {
			origHandler     = globalExceptHdl;
			globalExceptHdl = exception_handler;
		}
	} else {
		/* uninstall */
		if ( globalExceptHdl != exception_handler ) {
			rval = -1;
		} else {
			globalExceptHdl = origHandler;
		}
	}
	rtems_interrupt_enable(flags);
	if ( rval ) {
		if (action)
			fprintf(stderr,"ERROR: exception handler already installed\n");
		else
			fprintf(stderr,"ERROR: exception handler has changed; cannot uninstall\n");
	}
	return rval;
}

void
rtems_gdb_tgt_set_pc(RtemsDebugMsg msg, int pc)
{
Thread_Control *tcb;
	if ( msg->frm ) {
		msg->frm->EXC_SRR0 = pc;
	} else if ( (tcb = get_tcb(msg->tid)) ) {
		tcb->Registers.pc = pc;
		_Thread_Enable_dispatch();
	}
}

int
rtems_gdb_tgt_insdel_breakpoint(int doins, int addr, int len)
{
Bpnt            found, slot;
volatile unsigned long   opcode, subst;


	for ( found = bpnts + (NUM_BPNTS - 1), slot = 0;
		  found >= bpnts;
		  found-- ) {
		if ( !found->opcode )
			slot = found;
		else if ( found->addr == (volatile unsigned long *)addr )
			break;
	}
	if ( found < bpnts )
		found = 0;

	/* here we have
	 *  found  -> matching entry, slot undefined
	 *  !found -> slot is either a free entry or 0 if none available
	 */
		
	/* we should insert and it's already there OR
	 * we should delete and it's already gone
	 */
	if ( (found && doins) || (!found && !doins) )
		return 0;

	if ( doins && !slot )
		return -1;

	subst = doins ? TRAP(slot-bpnts) : found->opcode;	

/* BEGIN LONJMP POSSIBLE */
	/* patch */
	/* longjmp should restore interrupt mask */
	opcode = do_patch((volatile unsigned long*)addr, subst);
/* END LONGJMP POSSIBLE */

	/* we are  safe now */

	if ( doins ) {
		slot->addr   = (volatile unsigned long *)addr;
		slot->opcode = opcode;
	} else {
		found->addr   = 0;
		found->opcode = 0;
	}
	return 0;
}

void
rtems_gdb_tgt_remove_all_bpnts()
{
Bpnt f;
int  i;
	for (i=0,f=bpnts; i<NUM_BPNTS; i++,f++) {
		if (f->opcode) {
			do_patch((volatile unsigned long*)f->addr, f->opcode);
			f->opcode = 0;
		}
	}
}

int
rtems_gdb_tgt_single_step(RtemsDebugMsg msg)
{
Thread_Control *tcb;

	if (msg->frm) return 0;

	if ( (tcb = get_tcb(msg->tid)) ) {
		/* just set SE in the TCB :-) */
		tcb->Registers.msr |= MSR_SE;
		_Thread_Enable_dispatch();
		return 0;
	}
	return -1;
}
