/* $Id$ */
/* Target BSP specific gdb stub helpers for powerpc/shared & derived */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/bspIo.h> /* printk */
#include <bsp.h>

#include "rtems-gdb-stub-ppc-shared.h"

#include <libcpu/raw_exception.h> 
#include <libcpu/spr.h> 
#include <libcpu/stackTrace.h>
#include <libcpu/cpuIdent.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBBSPEXT
#include <bsp/bspExt.h>
#endif

/* handle older RTEMS versions */
#if !defined(ASM_60X_IMISS_VECTOR) && defined(ASM_IMISS_VECTOR)
#define ASM_60X_IMISS_VECTOR ASM_IMISS_VECTOR
#endif
#if !defined(ASM_60X_DLMISS_VECTOR) && defined(ASM_DLMISS_VECTOR)
#define ASM_60X_DLMISS_VECTOR ASM_DLMISS_VECTOR
#endif
#if !defined(ASM_60X_DSMISS_VECTOR) && defined(ASM_DSMISS_VECTOR)
#define ASM_60X_DSMISS_VECTOR ASM_DSMISS_VECTOR
#endif

#define get_tcb(tid) rtems_gdb_get_tcb_dispatch_off(tid)

/* cf. COMMON_UISA_REGS & friends in gdb/rs6000-tdep.c */
#define GPR0_OFF  (0)
#define FPR0_OFF  (32*4)
#define PC___OFF  (32*4+32*8+4*0)
#define PS___OFF  (32*4+32*8+4*1)
#define CR___OFF  (32*4+32*8+4*2)
#define LR___OFF  (32*4+32*8+4*3)
#define CTR__OFF  (32*4+32*8+4*4)
#define XER__OFF  (32*4+32*8+4*5)
#define FPSCR_OFF (32*4+32*8+4*6)

typedef struct BpntRec_ *Bpnt;

typedef struct BpntRec_ {
	volatile unsigned long *addr;
	unsigned long opcode;
} BpntRec;

#ifndef MSR_BOOKE_DE
#define MSR_BOOKE_DE	(1<<(63-54))
#endif

#define BOOKE_DBSR	304
#define BOOKE_DBCR0	308

#define PPC405_DBSR  0x3f0
#define PPC405_DBCR0 0x3f2

/* instruction complete */
#define DBCR0_ICMP (1<<(63-36))
#define DBCR0_IDM  (1<<(63-33))

SPR_RW(BOOKE_DBSR)
SPR_RW(BOOKE_DBCR0)
SPR_RW(PPC405_DBSR)
SPR_RW(PPC405_DBCR0)

static int isBookE = 0;

uint32_t mfmsr()
{
	return _read_MSR();
}

uint32_t mfdbsr()
{
	return PPC_BOOKE_405 == isBookE ? _read_PPC405_DBSR() : _read_BOOKE_DBSR();
}

uint32_t mfdbcr0()
{
	return PPC_BOOKE_405 == isBookE ? _read_PPC405_DBCR0() : _read_BOOKE_DBCR0();
}

#define NUM_BPNTS 32

static BpntRec bpnts[NUM_BPNTS] = {{0}};

#define TRAP(no) (0x0ce00000 + ((no)&0xffff)) /* twi 7,0,no */
#define TRAPNO(opcode) ((int)(((opcode) & 0xffff0000) == TRAP(0) ? (opcode)&0xffff : -1))

static inline unsigned long
do_patch(volatile unsigned long *addr, unsigned long val)
{
unsigned long rval;
unsigned key;

	rval = *addr;

	rtems_interrupt_disable(key);

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
		/* add 'key' to input operands to make sure this asm is not
		 * moved around
		 */
		::"r"(isBookE ? 0 : MSR_DR), "b"(addr), "r"(val), "r"(key)
		:"r0","r7");

	rtems_interrupt_enable(key);
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
#ifndef _SOFT_FLOAT
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			memcpy(buf + FPR0_OFF, &fpc->f[0], 32*8 );
			memcpy(buf + FPSCR_OFF, &fpc->fpscr, 4);
		}
#endif
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
#ifndef _SOFT_FLOAT
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			memcpy(&fpc->f[0],   buf+FPR0_OFF,    32*8 );
			memset(&fpc->fpscr,  0,               sizeof(fpc->fpscr));
			memcpy(&fpc->fpscr,  buf + FPSCR_OFF, 4);
		}
#endif
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

typedef struct PPC_Frame_ {
	struct PPC_Frame_ *up;
	void			  *lr;
} *PPC_Frame;

void
rtems_gdb_tgt_dump_frame(BSP_Exception_frame *f)
{
int		  i;
PPC_Frame p;
	/* rely on layout of BSP_Exception_Frame */
	printk("PPC Exception vector #0x%x\nRegister Contents:", f->_EXC_number);
	for ( i=0; i<32; i++ ) {
		if ( i%4 == 0 )
			printk("\n");
		printk("\tGPR%02d: 0x%08x",i,*(&f->GPR0 + i));
	}
	printk("\nMSR: 0x%08x; CTR: 0x%08x; CR: 0x%08x; XER: 0x%08x\n",
		f->EXC_SRR1, f->EXC_CTR, f->EXC_CR, f->EXC_XER);
	printk("\nPC: 0x%08x; LR: 0x%08x\n",
		f->EXC_SRR0, f->EXC_LR);
	if ( ( p = (PPC_Frame)f->GPR1 ) ) {
		printk("Stack trace:");
		for (i=0; (p=p->up) && i<50; i++) {
			if ( i%4 == 0 )
				printk("\n");
			printk("-> 0x%08x",p->lr);
		}
		printk("\n");
	}
}

static inline int
exception_handler(BSP_Exception_frame *f, void *unused)
{
static struct {
	int 			trapno;
	unsigned long	msr;
	int				sig;
} stepOverState = { -1,0,0 };
RtemsDebugMsgRec msg;

	if (   !_Thread_Executing 
		|| (RTEMS_SUCCESSFUL!=rtems_task_ident(RTEMS_SELF,RTEMS_LOCAL, &msg.tid)) ) {
		/* unable to deal with this situation */
		return -1;
	}

	if ( _Thread_Dispatch_disable_level > 1 ) {
		switch ( f->_EXC_number ) {
			case ASM_SYS_VECTOR:
			case ASM_TRACE_VECTOR:
				printk("rtems-gdb-stub: Fatal Error\n");
				printk("Cannot break into thread-dispatch disabled code or ISR\n");
			default:
				return -1;
		}
	}

	KDBGMSG(DEBUG_SCHED, "Task %x got exception %i, frame %x, GPR1 %x, IP %x\n\n",
							msg.tid,f->_EXC_number, f, f->GPR1, f->EXC_SRR0);

	/* the debugger should be able to handle its own exceptions */
	msg.frm = f;
	msg.sig = SIGHUP;

	switch ( f->_EXC_number ) {
		case ASM_MACH_VECTOR     :
#if 0
			_BSP_clear_hostbridge_errors(1,0);
#else
#warning TSILLXXXXXXXXXXXXXXX
#endif
			msg.sig = SIGBUS;
		break;

		case ASM_PROT_VECTOR     :
		case ASM_ISI_VECTOR      :
		case ASM_ALIGN_VECTOR    :  
		case ASM_60X_IMISS_VECTOR    :
		case ASM_60X_DLMISS_VECTOR   :
		case ASM_60X_DSMISS_VECTOR   :
			msg.sig = SIGSEGV;
		break;

		case ASM_PROG_VECTOR     :
			/* did we run into a soft breakpoint ? */
			msg.sig = TRAPNO(*(volatile unsigned long*)f->EXC_SRR0) < 0 ? SIGILL : SIGCHLD;
		break;

		case ASM_FLOAT_VECTOR    :
			msg.sig = SIGFPE;
		break;

		case ASM_DEC_VECTOR      :  
			msg.sig = SIGALRM;
		break;

		case ASM_SYS_VECTOR      :
			msg.sig = SIGCHLD;
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
					return 0;
				}
			}
			/* in any case, we should switch SE/DE off now.
			 * It is possible to end up here if they attach
			 * to a thread without breakpoint (step after
			 * task_switch_to())
			 */
			if ( isBookE ) {
				f->EXC_SRR1 &= ~MSR_BOOKE_DE;
			} else {
				f->EXC_SRR1 &= ~MSR_SE;
			}
			msg.sig = SIGTRAP;
		break;

		default: break;
	}
#ifndef _SOFT_FLOAT
	if (f->EXC_SRR1 & MSR_FP) {
		/* thread dispatching is _not_ disabled at this point; hence
		 * we must make sure we have the FPU enabled...
		 * original MSR will be restored anyways.
		 */
		_write_MSR( _read_MSR() | MSR_FP );
		__asm__ __volatile__("isync");
	}
#endif

	if ( rtems_gdb_notify_and_suspend(&msg) ) {
		return -1;
	}

	KDBGMSG(DEBUG_SCHED, "Resumed from exception; contSig %i, sig %i, GPR1 0x%08x PC 0x%08x LR 0x%08x\n",
						msg.contSig, msg.sig, msg.frm->GPR1, msg.frm->EXC_SRR0, msg.frm->EXC_LR);

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
		f->EXC_SRR1 &= ~ppc_interrupt_get_disable_mask();
		if ( isBookE ) {
			f->EXC_SRR1 |= MSR_BOOKE_DE;
			/* make sure there are no pending events */
			if ( PPC_BOOKE_405 == isBookE ) {
				_write_PPC405_DBSR(-1);
				_write_PPC405_DBCR0(DBCR0_ICMP | DBCR0_IDM);
			} else {
				_write_BOOKE_DBSR(-1);
				_write_BOOKE_DBCR0(DBCR0_ICMP | DBCR0_IDM);
			}
		} else {
			f->EXC_SRR1 |= MSR_SE;
		}
	} else {
		stepOverState.sig = 0;
	}
	return 0;
}

#ifndef HAVE_LIBBSPEXT
static void (*origHandler)()=0;

static void ehWrap(BSP_Exception_frame *f)
{
	if ( exception_handler(f,0) )
		origHandler();
}
#endif


int
rtems_gdb_tgt_install_ehandler(int action)
{
int rval = 0;
#ifndef HAVE_LIBBSPEXT
uint32_t flags;
#endif

	isBookE = ppc_cpu_is_bookE();

	if ( isBookE ) {
		/* Clear all pending debug exceptions
		 * and disable them for now; we'll enable
		 * the ones we need later.
		 */
		if ( PPC_BOOKE_405 == isBookE ) {
			_write_PPC405_DBSR(-1);
			_write_PPC405_DBCR0(0);
		} else {
			_write_BOOKE_DBSR(-1);
			_write_BOOKE_DBCR0(0);
		}
	}

#ifndef HAVE_LIBBSPEXT

	rtems_interrupt_disable(flags);
	if ( action ) {
		/* install */
		if ( globalExceptHdl == ehWrap ) {
			rval = -1;
		} else {
			origHandler     = globalExceptHdl;
			globalExceptHdl = ehWrap;
		}
	} else {
		/* uninstall */
		if ( globalExceptHdl != ehWrap ) {
			rval = -1;
		} else {
			globalExceptHdl = origHandler;
		}
	}
	rtems_interrupt_enable(flags);
#else
	if ( action ) {
		rval = bspExtInstallEHandler( exception_handler, 0, 1 /* head */ );
	} else {
		rval = bspExtRemoveEHandler( exception_handler, 0 );
	}
#endif
	if ( rval ) {
		ERRMSG("ERROR: exception handler %s\n",
				action ? "already installed" : "has changed; cannot uninstall");
	}
	return rval;
}

void
rtems_gdb_tgt_set_pc(RtemsDebugMsg msg, unsigned long pc)
{
	assert( msg->frm );
	msg->frm->EXC_SRR0 = pc;
}

unsigned long
rtems_gdb_tgt_get_pc(RtemsDebugMsg msg)
{
	assert( msg->frm );
	return msg->frm->EXC_SRR0;
}

int
rtems_gdb_tgt_insdel_breakpoint(int doins, int addr, int len)
{
Bpnt            found, slot;
volatile unsigned long   opcode, subst;

	if ( len > 4 )
		return -1;

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
		if ( isBookE ) {
			tcb->Registers.msr |= MSR_BOOKE_DE;
			/* make sure there are no pending events */
			if ( PPC_BOOKE_405 == isBookE ) {
				_write_PPC405_DBSR(-1);
				_write_PPC405_DBCR0(DBCR0_ICMP | DBCR0_IDM);
			} else {
				_write_BOOKE_DBSR(-1);
				_write_BOOKE_DBCR0(DBCR0_ICMP | DBCR0_IDM);
			}
		} else {
			/* just set SE in the TCB :-) */
			tcb->Registers.msr |= MSR_SE;
		}
		_Thread_Enable_dispatch();
		return 0;
	}
	return -1;
}

#if 0
int faul()
{
Frame sp;
unsigned long lr;
	asm volatile("mr %0, 1; mflr %1":"=r"(sp),"=r"(lr));
	printf("LR 0x%08lx; SP %p; *SP %p; **SP %p\n",
		lr, sp, sp->up, sp->up->up);
	return (int)sp;
}
#endif
