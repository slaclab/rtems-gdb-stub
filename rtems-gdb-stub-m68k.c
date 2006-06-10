/* $Id$ */

/* Target BSP specific gdb stub helpers for m68k */

/* NOTE: THIS IS A DEMO/EXPERIMENTAL IMPLEMENTATION WHICH WAS NOT VERY
 *       CAREFULLY WRITTEN -- PLEASE REVIEW
 */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/bspIo.h> /* printk */

#include "rtems-gdb-stub-m68k.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>

#define get_tcb(tid) rtems_gdb_get_tcb_dispatch_off(tid)

#define NUM_BPNTS 250

/* breakpoint instruction */
#define TRAP0 0x4e40

/* indices into saved handler array */
#define ACCESS_HDL	0
#define TRAP0_HDL	1
#define TRACE_HDL	2

#define ACCESS_VEC	2
#define TRAP0_VEC	32
#define TRACE_VEC	9

#define PS_TRACE	(1<<15)

/* from cpu_asm.S: (offsets in BYTES) */
#define SAVED         16
#if ( M68K_COLDFIRE_ARCH == 1 )
#define SR_OFFSET     2                     /* Status register offset */
#define PC_OFFSET     4                     /* Program Counter offset */
#define FVO_OFFSET    0                     /* Format/vector offset */
#elif ( M68K_HAS_VBR == 1)
#define SR_OFFSET     0                     /* Status register offset */
#define PC_OFFSET     2                     /* Program Counter offset */
#define FVO_OFFSET    6                     /* Format/vector offset */
#else
#define SR_OFFSET     2                     /* Status register offset */
#define PC_OFFSET     4                     /* Program Counter offset */
#define FVO_OFFSET    0                     /* Format/vector offset placed in the stack */
#endif /* M68K_HAS_VBR */

static struct {
	void    (*hdl)();
	uint32_t  vec;
} origHandlerTbl[]={
	{ 0,	ACCESS_VEC,	/* Access */ },
	{ 0,	TRAP0_VEC,	/* TRAP0  */ },
	{ 0,	TRACE_VEC,	/* TRACE  */ },
};


typedef uint16_t TrapCode;

/* Breakpoint implementation; a simple linked list
 * (as I said, m68k support is not very sophisticated)
 */
static struct bpnt_ {
	struct bpnt_ *next;
	unsigned long addr;
	TrapCode      code;
} bpntTab[NUM_BPNTS] = {{0}};

static struct bpnt_ bpnts      = {0}; /* anchor el. */
static struct bpnt_ *bpntsFree = 0;

/* cf. gdb/m68k-tdep.c */

int
rtems_gdb_tgt_regoff(int regno, int *poff)
{
*poff = 0;
	if ( regno < M68K_D0_REGNUM || regno > M68K_PC_REGNUM )
		return -1;
	*poff += regno*4;
	return 4;
}

int
tdumpctxt(rtems_id tid)
{
Thread_Control *tcb;
Context_Control r;
	if ( (tcb = get_tcb(tid)) ) {
		r = tcb->Registers;
		_Thread_Enable_dispatch();
		printk("D2: 0x%08x  ", r.d2); printk("D3: 0x%08x  ", r.d3); printk("D4: 0x%08x\n", r.d4);
		printk("D5: 0x%08x  ", r.d5); printk("D6: 0x%08x  ", r.d6); printk("D7: 0x%08x\n", r.d7);
		printk("A2: 0x%08x  ", r.a2); printk("A3: 0x%08x  ", r.a3); printk("A4: 0x%08x\n", r.a4);
		printk("A5: 0x%08x  ", r.a5); printk("A6: 0x%08x  ", r.a6); printk("\n");

		printk("SP: 0x%08x  PS: 0x%08x\n", r.a7_msp, r.sr);
		return 0;
	}
	return -1;
}

/* map exception frame into register array (GDB layout) */
void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugMsg msg)
{
Thread_Control *tcb;
RtemsDebugFrame f = msg->frm;
int             deadbeef = 0xdeadbeef;

	memset(buf, 0, NUMREGBYTES);

	if ( f ) {
		memcpy(buf, f->regs.d, 16*4);
		*(uint32_t*)(buf + M68K_PS_REGNUM*4) = f->regs.ps;
		*(uint32_t*)(buf + M68K_PC_REGNUM*4) = f->regs.pc;
		/* TODO: copy FP context */
	} else {
		memcpy(buf + M68K_D0_REGNUM*4, &deadbeef, 4);
		memcpy(buf + M68K_D1_REGNUM*4, &deadbeef, 4);
		memcpy(buf + M68K_A0_REGNUM*4, &deadbeef, 4);
		memcpy(buf + M68K_A1_REGNUM*4, &deadbeef, 4);
	}

	if ( (tcb = get_tcb(msg->tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
#warning TODO copy FP regs
		}
		if (!f) {
			memcpy(buf + M68K_D2_REGNUM*4, &tcb->Registers.d2, 4);
			memcpy(buf + M68K_D3_REGNUM*4, &tcb->Registers.d3, 4);
			memcpy(buf + M68K_D4_REGNUM*4, &tcb->Registers.d4, 4);
			memcpy(buf + M68K_D5_REGNUM*4, &tcb->Registers.d5, 4);
			memcpy(buf + M68K_D6_REGNUM*4, &tcb->Registers.d6, 4);
			memcpy(buf + M68K_D7_REGNUM*4, &tcb->Registers.d7, 4);
			memcpy(buf + M68K_A2_REGNUM*4, &tcb->Registers.a2, 4);
			memcpy(buf + M68K_A3_REGNUM*4, &tcb->Registers.a3, 4);
			memcpy(buf + M68K_A4_REGNUM*4, &tcb->Registers.a4, 4);
			memcpy(buf + M68K_A5_REGNUM*4, &tcb->Registers.a5, 4);
			memcpy(buf + M68K_FP_REGNUM*4, &tcb->Registers.a6, 4);
			memcpy(buf + M68K_SP_REGNUM*4, &tcb->Registers.a7_msp, 4);
			memcpy(buf + M68K_PS_REGNUM*4, &tcb->Registers.sr, 4);
			memcpy(buf + M68K_PC_REGNUM*4, (uint32_t*)tcb->Registers.a7_msp, 4);
		}
		_Thread_Enable_dispatch();
	}
}

#define YPCMEM(fr, to, sz) memcpy((to), (fr), (sz))

/* register array (GDB layout) to exception frame */
void
rtems_gdb_tgt_r2f(RtemsDebugMsg msg, unsigned char *buf)
{
Thread_Control *tcb;
RtemsDebugFrame f = msg->frm;
int            deadbeef = 0xdeadbeef;

	if ( f ) {
		YPCMEM(buf, f->regs.d, 16*4);
		f->regs.ps = *(uint32_t*)(buf + M68K_PS_REGNUM*4);
		f->regs.pc = *(uint32_t*)(buf + M68K_PC_REGNUM*4);
	} else {
		YPCMEM(buf + M68K_D0_REGNUM*4, &deadbeef, 4);
		YPCMEM(buf + M68K_D1_REGNUM*4, &deadbeef, 4);
		YPCMEM(buf + M68K_A0_REGNUM*4, &deadbeef, 4);
		YPCMEM(buf + M68K_A1_REGNUM*4, &deadbeef, 4);
	}

	if ( (tcb = get_tcb(msg->tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
#warning TODO copy FP regs
		}
		if (!f) {
			YPCMEM(buf + M68K_D2_REGNUM*4, &tcb->Registers.d2, 4);
			YPCMEM(buf + M68K_D3_REGNUM*4, &tcb->Registers.d3, 4);
			YPCMEM(buf + M68K_D4_REGNUM*4, &tcb->Registers.d4, 4);
			YPCMEM(buf + M68K_D5_REGNUM*4, &tcb->Registers.d5, 4);
			YPCMEM(buf + M68K_D6_REGNUM*4, &tcb->Registers.d6, 4);
			YPCMEM(buf + M68K_D7_REGNUM*4, &tcb->Registers.d7, 4);
			YPCMEM(buf + M68K_A2_REGNUM*4, &tcb->Registers.a2, 4);
			YPCMEM(buf + M68K_A3_REGNUM*4, &tcb->Registers.a3, 4);
			YPCMEM(buf + M68K_A4_REGNUM*4, &tcb->Registers.a4, 4);
			YPCMEM(buf + M68K_A5_REGNUM*4, &tcb->Registers.a5, 4);
			YPCMEM(buf + M68K_FP_REGNUM*4, &tcb->Registers.a6, 4);
			YPCMEM(buf + M68K_SP_REGNUM*4, &tcb->Registers.a7_msp, 4);
			YPCMEM(buf + M68K_PS_REGNUM*4, &tcb->Registers.sr, 4);
			YPCMEM(buf + M68K_PC_REGNUM*4, (uint32_t*)tcb->Registers.a7_msp, 4);
		}
		_Thread_Enable_dispatch();
	}
}

#undef YPCMEM

void
rtems_gdb_tgt_dump_frame(RtemsDebugFrame f)
{
int i;
	printk("Exception vector #%u (0x%x); Registers:\n",f->vector, f->vector);
	for (i=0; i<8;) {
		printk("D%i: 0x%08x  ",i,f->regs.d[i]);
		if ( ++i%4 == 0 )
			printk("\n");
	}
	for (i=0; i<8;) {
		printk("A%i: 0x%08x  ",i,f->regs.a[i]);
		if ( ++i%4 == 0 )
			printk("\n");
	}
	printk("PC: 0x%08x; PS: 0x%04x; FVO: 0x%04x\n", f->regs.pc, f->regs.ps, f->regs.fvo);
}

/* Need an ASM wrapper to save all registers; these go onto the interrupt stack */
extern rtems_isr _m68k_gdb_exception_wrapper();
extern void      _m68k_gdb_frame_cleanup();

static void
exception_handler(RtemsDebugFrame f)
{
int		 oh_idx = ACCESS_HDL;	/* pick ACCESS for default */

	if ( /*  rtems_interrupt_is_in_progress()
	    ||*/ !_Thread_Executing 
		|| (RTEMS_SUCCESSFUL!=rtems_task_ident(RTEMS_SELF,RTEMS_LOCAL, &f->msg.tid)) ) {
		/* unable to deal with this situation */
		origHandlerTbl[oh_idx].hdl(f->vector);
		return;
	}

	KDBGMSG(DEBUG_SCHED, "Task %x got exception %i, frame %x, SP %x, IP %x\n\n",
		f->msg.tid, f->vector, f, f->regs.a[7], f->regs.pc);

	/* the debugger should be able to handle its own exceptions */
	f->msg.frm = f;
	f->msg.sig = SIGHUP;

	switch ( f->vector ) {
		case ACCESS_VEC:
			oh_idx  = ACCESS_HDL;
			f->msg.sig = SIGSEGV;
		break;

		case TRACE_VEC:
			f->msg.sig = SIGTRAP;
			f->regs.ps &= ~PS_TRACE;

		break;

#if 0
		case 1:  /* debug exception */
		f->msg.sig = SIGTRAP;
		/* reset single step flag */
		f->eflags &= ~EFLAGS_TRAP;
		break;
		case 6:  /* invalid opcode  */
		f->msg.sig = SIGILL;
		break;

		case 7:  /* FPU not avail.  */
		case 8:  /* double fault    */
		case 9:  /* i387 seg overr. */
		case 16: /* fp error        */
		f->msg.sig = SIGFPE;
		break;

		case 5:  /* out-of-bounds   */
		case 10: /* Invalid TSS     */
		case 11: /* seg. not pres.  */
		case 12: /* stack except.   */
		case 13: /* general prot.   */
		case 14: /* page fault      */
		case 17: /* alignment check */
		f->msg.sig = SIGSEGV;
		break;

		case 2:  /* NMI             */
		case 18: /* machine check   */
		f->msg.sig = SIGBUS;
		break;

#endif

		case TRAP0_VEC:  /* breakpoint trap 0 */
			oh_idx = TRAP0_HDL;
			f->msg.sig = SIGCHLD;
			/* adjust PC */
			f->regs.pc -= 2;
		break;

		break;

		default: break;
	}

#if 1
	if ( rtems_gdb_notify_and_suspend(&f->msg) ) {
		origHandlerTbl[oh_idx].hdl(f->vector);
		return;
	}
#endif

	KDBGMSG(DEBUG_SCHED, "Resumed from exception; contSig %i, sig %i, SP 0x%08x PC 0x%08x BP 0x%08x\n",
		f->msg.contSig, f->msg.sig, f->msg.frm->regs.a[7], f->msg.frm->regs.pc, f->msg.frm->regs.a[6]);

	if ( SIGCONT != f->msg.contSig ) {
		f->msg.frm->regs.ps |= PS_TRACE;
	}
}

void
_m68k_gdb_exception_handler(int arg)
{
M68k_ExceptionFrame frame = (M68k_ExceptionFrame)&arg;
uint32_t            *p = frame->usr_stack;
M68k_GdbFrame       gf;

	/* fixup the data in the frame; only d2..d7, a2..a6 are valid now */

	/* see m68k cpu_asm.S for details -- this code DEPENDS on cpu_asm.S details */

	/* it would probably be better to make changes there and provide a generic
         * API for low-level exception handling...
	 */

	frame->regs.d[0] = p[0];
	frame->regs.d[1] = p[1];

	frame->regs.a[0] = p[2];
	frame->regs.a[1] = p[3];

	frame->regs.a[7] = (uint32_t)p + SAVED + 8;

	frame->regs.ps   = *(uint16_t*)((uint32_t)p + SAVED + SR_OFFSET);
	frame->regs.fvo  = *(uint16_t*)((uint32_t)p + SAVED + FVO_OFFSET);

	frame->regs.pc   = *(uint32_t*)((uint32_t)p + SAVED + PC_OFFSET);

printk("TSILL EXCEPTION\n");
#if 1
	/* test if modifying the user stack works */
	/* wipe out */
	memset(p,0,SAVED+8);
#endif

	p = frame->usr_stack = (uint32_t *)(frame->regs.a[7] - 8 - sizeof(M68k_GdbFrameRec) - 8 - SAVED);
	gf = (M68k_GdbFrame)(p+6);

	gf->vector    = frame->vector;
	gf->size      = sizeof(*gf);
	gf->msg.frm   = gf;
	gf->regs      = frame->regs;
	
	/* fixup the user stack */
	p[0] = frame->regs.d[0];
	p[1] = frame->regs.d[1];
	p[2] = frame->regs.a[0];
	p[3] = frame->regs.a[1];


	*(uint16_t*)((uint32_t)p + SAVED + SR_OFFSET)  = frame->regs.ps;
	*(uint16_t*)((uint32_t)p + SAVED + FVO_OFFSET) = frame->regs.fvo;
	*(uint32_t*)((uint32_t)p + SAVED + PC_OFFSET)  = (uint32_t)_m68k_gdb_frame_cleanup;

}

static int
isr_restore(int n)
{
int       rval = 0;
rtems_isr (*dummy)(rtems_vector_number);
	while (--n >= 0) {
		rval = rval || rtems_interrupt_catch(origHandlerTbl[n].hdl, origHandlerTbl[n].vec, &dummy);
		origHandlerTbl[n].hdl = 0;
	}
	return rval;
}

int
rtems_gdb_tgt_install_ehandler(int action)
{
int rval = 0, i;

	/* initialize breakpoint table */
	for ( i=0; i<NUM_BPNTS-1; i++ )
		bpntTab[i].next = bpntTab+i+1;
	bpntsFree = bpntTab;

	if ( action ) {
		/* install */
		for ( i = 0; i<sizeof(origHandlerTbl)/sizeof(origHandlerTbl[0]); i++ ) {
			if ( rtems_interrupt_catch(_m68k_gdb_exception_wrapper, origHandlerTbl[i].vec, &origHandlerTbl[i].hdl) ) {
				origHandlerTbl[i].hdl = 0;
				isr_restore(i);
				rval = -1;
				break;
			}
		}
	} else {
		/* uninstall */
		rval = isr_restore(sizeof(origHandlerTbl)/sizeof(origHandlerTbl[0]));
	}

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
	msg->frm->regs.pc = pc;
}

unsigned long
rtems_gdb_tgt_get_pc(RtemsDebugMsg msg)
{
	assert( msg->frm );
	return msg->frm->regs.pc;
}


static inline TrapCode
do_patch(volatile TrapCode *addr, uint16_t val)
{
uint16_t rval;
unsigned long flags;
extern void _CPU_cache_flush_1_data_line(void *addr);
extern void _CPU_cache_invalidate_1_instruction_line(void *addr);
	rtems_interrupt_disable(flags);
		rval  = *addr;
		*addr = val;
                _CPU_cache_flush_1_data_line((void*)addr);
                _CPU_cache_invalidate_1_instruction_line((void*)addr);
	rtems_interrupt_enable(flags);
	return rval;
}

int
rtems_gdb_tgt_insdel_breakpoint(int doins, int addr, int len)
{
struct bpnt_ *found, *prev;
uint16_t trap = TRAP0;

	if (len < sizeof(trap))
		return -1;

	/* find existing */
	for (prev = &bpnts; (found = prev->next); prev=found) {
		if ( found->addr == addr ) {
			break;
		}
	}

	/* redundant operation; already there or already deleted */
	if ( (found && doins) || (!found && !doins) )
		return 0;

/* EXCEPTION MAY LONGJMP OUT OF THIS SECTION */
	if ( doins ) {
		TrapCode code;
		if ( !bpntsFree )
			return -1;
		
		code = do_patch((void*)addr, TRAP0);
		
		/* if we made it that far, we succeeded */
		found        = bpntsFree;
		bpntsFree    = bpntsFree->next;
		found->next  = bpnts.next;
		bpnts.next   = found;
		found->addr  = addr;
		found->code  = code;
	} else {
		do_patch((void*)addr, found->code);
		/* if we made it that far, we succeeded */
		prev->next   = found->next;
		found->next  = bpntsFree;
		bpntsFree    = found;
		found->addr  = 0;
		found->code  = 0;
	}
/* END OF LONGJMP SENSITIVE SECTION          */
	
return 0;
}

void
rtems_gdb_tgt_remove_all_bpnts()
{
struct bpnt_ *found;
	/* hopefully, this doesn't segfault */
	while ( (found = bpnts.next) ) {
		do_patch((void*)found->addr, found->code);
		bpnts.next  = found->next;
		found->next = bpntsFree;
		bpntsFree   = found;
		found->addr = 0; 
		found->code = 0;
	}
}

int
rtems_gdb_tgt_single_step(RtemsDebugMsg msg)
{
	return -1;
}

void
_fdebug(M68k_GdbFrameRec r)
{
#if 0
	/* branch to main exception handler */
	exception_handler(&r);
#endif

	/* fixup registers */
	r.regs.a[7] = (uint32_t)&r + sizeof(M68k_GdbFrameRec);
	*(uint16_t*)((uint32_t)&r + sizeof(M68k_GdbFrameRec) + SR_OFFSET)  = r.regs.ps;
	*(uint16_t*)((uint32_t)&r + sizeof(M68k_GdbFrameRec) + FVO_OFFSET) = r.regs.fvo;
	*(uint32_t*)((uint32_t)&r + sizeof(M68k_GdbFrameRec) + PC_OFFSET)  = r.regs.pc;
rtems_gdb_tgt_dump_frame(&r);
}
