/* $Id$ */

/* Target BSP specific gdb stub helpers for m68k */

/* NOTE: THIS IS A DEMO/EXPERIMENTAL IMPLEMENTATION WHICH WAS NOT VERY
 *       CAREFULLY WRITTEN -- PLEASE REVIEW
 */

/* Author: Till Straumann, <strauman@slac.stanford.edu>, 2006 */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/bspIo.h> /* printk */

#include "rtems-gdb-stub-m68k.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <inttypes.h>

#define get_tcb(tid) rtems_gdb_get_tcb_dispatch_off(tid)

#define NUM_BPNTS 25

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

/* Need an ASM wrapper to save all registers; these go onto the interrupt stack */
extern rtems_isr _m68k_gdb_exception_wrapper(); /* passes control to _m68k_gdb_exception_handler() */
/* Need an ASM helper to pop and reload all registers from the GDB frame ('longjump' back to thread) */
extern void      _m68k_gdb_frame_cleanup();     /* passes control to _m68k_gdb_ret_to_thread() */


/* little table of all vectors we hook into */
static struct {
	void    (*hdl)();
	uint32_t  vec;
} origHandlerTbl[]={
	{ 0,	ACCESS_VEC,	/* Access */ },
	{ 0,	TRAP0_VEC,	/* TRAP0  */ },
	{ 0,	TRACE_VEC,	/* TRACE  */ },
};

static void
oh_dispatch(int i)
{
	if ( i >=0 && i<sizeof(origHandlerTbl)/sizeof(origHandlerTbl[0]) && origHandlerTbl[i].hdl )
		origHandlerTbl[i].hdl(origHandlerTbl[i].vec);
}

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
rtems_m68k_dump_task_regs(rtems_id tid)
{
Thread_Control *tcb;
Context_Control r;
	if ( (tcb = get_tcb(tid)) ) {
		r = tcb->Registers;
		_Thread_Enable_dispatch();
		printf("D2: 0x%08"PRIx32"  ", r.d2); printf("D3: 0x%08"PRIx32"  ", r.d3); printf("D4: 0x%08"PRIx32"\n", r.d4);
		printf("D5: 0x%08"PRIx32"  ", r.d5); printf("D6: 0x%08"PRIx32"  ", r.d6); printf("D7: 0x%08"PRIx32"\n", r.d7);
		printf("A2: 0x%08"PRIx32"  ", (uint32_t)r.a2); printf("A3: 0x%08"PRIx32"  ", (uint32_t)r.a3); printf("A4: 0x%08"PRIx32"\n", (uint32_t)r.a4);
		printf("A5: 0x%08"PRIx32"  ", (uint32_t)r.a5); printf("A6: 0x%08"PRIx32"  ", (uint32_t)r.a6); printf("\n");

		printf("SP: 0x%08"PRIx32"  PS: 0x%08"PRIx32"\n", (uint32_t)r.a7_msp, r.sr);
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
		*(uint32_t*)(buf + M68K_PS_REGNUM*4) = f->ret_info.ps;
		*(uint32_t*)(buf + M68K_PC_REGNUM*4) = f->ret_info.pc;
		/* TODO: copy FP context */
	} else {
		memcpy(buf + M68K_D0_REGNUM*4, &deadbeef, 4);
		memcpy(buf + M68K_D1_REGNUM*4, &deadbeef, 4);
		memcpy(buf + M68K_A0_REGNUM*4, &deadbeef, 4);
		memcpy(buf + M68K_A1_REGNUM*4, &deadbeef, 4);
	}

	if ( (tcb = get_tcb(msg->tid)) ) {
#if CPU_HARDWARE_FP == TRUE
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
#warning TODO copy FP regs
		}
#endif
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
		f->ret_info.ps = *(uint32_t*)(buf + M68K_PS_REGNUM*4);
		f->ret_info.pc = *(uint32_t*)(buf + M68K_PC_REGNUM*4);
	} else {
		YPCMEM(buf + M68K_D0_REGNUM*4, &deadbeef, 4);
		YPCMEM(buf + M68K_D1_REGNUM*4, &deadbeef, 4);
		YPCMEM(buf + M68K_A0_REGNUM*4, &deadbeef, 4);
		YPCMEM(buf + M68K_A1_REGNUM*4, &deadbeef, 4);
	}

	if ( (tcb = get_tcb(msg->tid)) ) {
#if CPU_HARDWARE_FP == TRUE
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
#warning TODO copy FP regs
		}
#endif
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
	printk("Exception vector #%u (0x%x) [frame @0x%08x]; Registers:\n",f->vector, f->vector, f);
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
	printk("PC: 0x%08x; PS: 0x%04x; FVO: 0x%04x\n", f->ret_info.pc, f->ret_info.ps, f->ret_info.fvo);
}

/* Here comes the low-level exception handler.
 * Unfortunately, on this platform things are a bit complex.
 * The gdb daemon assumes a thread incurring an exception (trap or fault)
 * suspends itself in the middle of the exception handler where the full
 * register info is available.
 * The 68k code (cpu_asm.S) however, disables thread dispatching during
 * execution of the handler (must do so since a single ISR stack is used
 * and cpu_asm.S assumes that only one thread at a time uses the special
 * stack).
 * Therefore, we must play some dirty tricks:
 *  1) Our low-level handler first has to gather all the register info
 *     (cpu_asm doesn't save and pass a complete frame to the exception
 *     handler).
 *     d2..d7, a2..a6 are saved onto the ISR stack by the assembly wrapper
 *     around _m68k_gdb_exception_handler (C-code could clobber d2..a6).
 *     d0,d1,a0,a2,ps,pc,fvo are retrieved from the user stack where
 *     _ISR_Handler stored them.
 *     (hence this code depends on ISR_Handler implementation :-().
 *
 *     At this point, the stacks look like this:
 *
 *        user stack                             ISR stack
 *
 *         [trapped thread]                .---- ptr to usr stack
 *         8-bytes return info (PS,PC)     .     vector
 *           pushed by CPU on trap         .     <rtn addr to _ISR_Handler>
 *         a1                              .     a7 regs pushed by 
 *         a0                              .     .. our wrapper.
 *         d1                              .     a2 (a7 used as local var below)
 *         d0                   <----------.
 *
 *  2) User stack is manipulated so a 'top-half' of exception handling
 *     code is executed later, when thread dispatching is enabled again.
 *     the 'top-half' can then safely suspend itself and post to the daemon.
 *
 *        user stack                             ISR stack
 *
 *   ....  [trapped thread]                .---- ptr to usr stack
 *         8-bytes return info (PS,PC)     .     vector
 *   'GDB' (return to thread)              .     <rtn addr to _ISR_Handler>
 *   frame 'msg' struct                    .     a7 regs pushed by 
 *   ....  'all registers'                 .     .. our wrapper.
 *         8-bytes return info (PS,PC)     .     d2 (a7 used as local var below)
 *         (to _m68k_gdb_frame_cleanup)    .
 *         a1                              .
 *         a0                              .
 *         d1                              .
 *         d0                   <----------.
 *
 *  3) after _m68k_gdb_exception_handler terminates, control is passed back through
 *     the wrapper (pops d2..a7) to _ISR_Handler which pops the vector from the
 *     ISR stack, switches the stack back, pops + reloads d0..a1 (not really needed)
 *     and jumps to _m68k_gdb_frame_cleanup() after finishing [thread dispatching has
 *     been enabled].
 *
 *  4) 'cleanup' (assembly in m68k-stackops.S) invokes _m68k_gdb_ret_to_thread()
 *     which does the ordinary processing of exceptions and posts the frame
 *     struct to the daemon.
 *
 *  5) If the thread is woken up, 8 'return info' bytes (GDB could have modified
 *     the PC) are stored on the usr stack and the SP (in the frame, not the real
 *     register contents) is adjusted to point there.
 *
 *  6) 'cleanup' pops d0..a7 from the stack. This reloads SP which now points
 *     to the final 'return info'. The 'rte' instruction then passes control
 *     back to the thread.
 *
 *  In addition to all this, 'switch_stack' can be used to move the entire
 *  user stack below what the thread is using to a private area while
 *  gdb is active (during suspension in 'notify_and_suspend') so gdb
 *  can manipulate the user stack as it wants.
 */

#define SAVED 16	/* space used by ISR_Handler to store d0,d1,a0,a1 */

/* 'Bottom' handler. Gathers all register info and pushes a RtemsDebugFrame struct
 * on the user stack. Bottom of the user stack is fixed up, so _ISR_Handler properly
 * unwraps it and passes control - not back to the thread - but to our 'cleanup'
 * AKA 'top-half' routine.
 */
void
_m68k_gdb_exception_handler(int arg)
{
M68k_ExceptionFrame frame = (M68k_ExceptionFrame)&arg;
uint32_t            *p = frame->usr_stack;
M68k_GdbFrame       gf;
M68k_RetInfo        ri;

	/* fixup the data in the frame; only d2..d7, a2..a6 are valid now */

	/* see m68k cpu_asm.S for details -- this code DEPENDS on cpu_asm.S details */

	/* it would probably be better to make changes there and provide a generic
	 * API for low-level exception handling...
	 */

	frame->regs.d[0] = p[0];
	frame->regs.d[1] = p[1];

	frame->regs.a[0] = p[2];
	frame->regs.a[1] = p[3];

	frame->regs.a[7] = (uint32_t)p + SAVED + sizeof(M68k_RetInfoRec);

	/* push all info on user stack */
	frame->usr_stack = (uint32_t *)(frame->regs.a[7] - sizeof(M68k_GdbFrameRec) - sizeof(M68k_RetInfoRec) - SAVED);
	gf = (M68k_GdbFrame)((unsigned)frame->usr_stack + SAVED + sizeof(M68k_RetInfoRec));

	/* copy return info into GdbFrame (not really necessary if GdbFrame is already on user stack) */
	gf->ret_info  = *(M68k_RetInfo)((uint32_t)p+SAVED);

	gf->vector    = frame->vector;
	gf->msg.frm   = gf;
	gf->regs      = frame->regs;
	
	/* fixup the user stack */
	p    = (uint32_t*) frame->usr_stack;
	p[0] = frame->regs.d[0];
	p[1] = frame->regs.d[1];
	p[2] = frame->regs.a[0];
	p[3] = frame->regs.a[1];

	ri = (M68k_RetInfo)((uint32_t)p+SAVED);

	/* copy return info below the stuff we pushed */
	ri->ps  = (gf->ret_info.ps & ~PS_TRACE);
	ri->fvo = gf->ret_info.fvo;
	/* jump to our frame cleanup routine when passing control from the ISR to the user stack */
	ri->pc  = (uint32_t)_m68k_gdb_frame_cleanup;
}

#undef SAVED

/* real work for 'top-half' exception handler */
static void
exception_handler(RtemsDebugFrame f)
{
int		 oh_idx = ACCESS_HDL;	/* pick ACCESS for default */

	if ( /*  rtems_interrupt_is_in_progress()
	    ||*/ !_Thread_Executing 
		|| (RTEMS_SUCCESSFUL!=rtems_task_ident(RTEMS_SELF,RTEMS_LOCAL, &f->msg.tid)) ) {
		/* unable to deal with this situation */
		oh_dispatch(f->vector);
		return;
	}

	KDBGMSG(DEBUG_SCHED, "Task %x got exception %i, frame %x, SP %x, IP %x\n\n",
		f->msg.tid, f->vector, f, f->regs.a[7], f->ret_info.pc);

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
			f->ret_info.ps &= ~PS_TRACE;

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
			f->ret_info.pc -= 2;
		break;

		break;

		default: break;
	}

	if ( rtems_gdb_notify_and_suspend(&f->msg) ) {
		oh_dispatch(f->vector);
		return;
	}

	KDBGMSG(DEBUG_SCHED, "Resumed from exception; contSig %i, sig %i, SP 0x%08x PC 0x%08x BP 0x%08x\n",
		f->msg.contSig, f->msg.sig, f->msg.frm->regs.a[7], f->msg.frm->ret_info.pc, f->msg.frm->regs.a[6]);

	if ( SIGCONT != f->msg.contSig ) {
		f->msg.frm->ret_info.ps |= PS_TRACE;
	}
}

#ifdef DEBUGGING_ENABLED
int rtems_gdb_m68k_freeze_resume=0;
#endif

/* top-half exception handler (itself wrapped by assembly code) */
void
_m68k_gdb_ret_to_thread(int arg)
{
M68k_GdbFrame r = (M68k_GdbFrame)&arg;

	/* branch to main exception handler */
	exception_handler(r);

	/* fixup registers */

	/* adjust stack to store return info */
	r->regs.a[7] -= sizeof(M68k_RetInfoRec);
	/* store return info */
	*((M68k_RetInfo)(r->regs.a[7])) = r->ret_info;

#ifdef DEBUGGING_ENABLED
	if ( rtems_gdb_m68k_freeze_resume ) {
		rtems_gdb_tgt_dump_frame(r);
		rtems_task_suspend(RTEMS_SELF);
	}
#endif
}

static void
dummyHandler(int vector)
{
	printk("Dumb exception handler; vector %i (0x%x) trapped; suspending task\n",vector,vector);
	rtems_task_suspend(RTEMS_SELF);
}

static int
isr_restore(int n)
{
int       rval = 0;
rtems_isr (*dummy)(rtems_vector_number);
	while (--n >= 0) {
		if ( ! origHandlerTbl[n].hdl ) {
			if ( ! rtems_gdb_nounload ) {
				/* if no handler was registered earlier then we're hosed */
				fprintf(stderr,"Cannot uninstall exception handler -- no old handler known\n");
				fprintf(stderr,"I'll install a dummy handler and lock this module in memory\n");
				rtems_gdb_nounload = 1;
			}
			origHandlerTbl[n].hdl = dummyHandler;
		}
		rval = (rval || rtems_interrupt_catch(origHandlerTbl[n].hdl, origHandlerTbl[n].vec, &dummy));
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
				action ? "already installed" : "cannot be removed; uninstall failed");
	}
	return rval;
}

void
rtems_gdb_tgt_set_pc(RtemsDebugMsg msg, unsigned long pc)
{
	assert( msg->frm );
	msg->frm->ret_info.pc = pc;
}

unsigned long
rtems_gdb_tgt_get_pc(RtemsDebugMsg msg)
{
	assert( msg->frm );
	return msg->frm->ret_info.pc;
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
