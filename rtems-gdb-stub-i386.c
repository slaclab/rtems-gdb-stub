/* $Id$ */

/* Target BSP specific gdb stub helpers for i386/pc586 & derived */

/* NOTE: THIS IS A DEMO/EXPERIMENTAL IMPLEMENTATION WHICH WAS NOT VERY
 *       CAREFULLY WRITTEN -- PLEASE REVIEW
 */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/bspIo.h> /* printk */

#include "rtems-gdb-stub-i386.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>

#define get_tcb(tid) rtems_gdb_get_tcb_dispatch_off(tid)

#define NUM_BPNTS 250

/* breakpoint instruction */
#define INT3 0xcc

/* GDB-6.2.1 / i386 has no frame_align method and doesn't honour
 * the red-zone :-(
 * Therefore, we must resort to a separate stack.
 * See 'switch_stack.c' for an explanation how it works...
 */

/* Define architecture specific stuff for i386 */

typedef struct FrameRec_ {
	struct FrameRec_ *up;
} FrameRec, *Frame;

#define STACK_ALIGNMENT 16 /* ?? */
#define FRAME_SZ        ((128+16*4+500)>>2)
#define SP_GET(sp)	do { asm volatile("movl %%esp, %0":"=r"(sp)); } while(0)
#define SP_PUT(val)	do { asm volatile("movl %0, %%esp"::"r"(val)); } while(0)
#define BP_GET(bp)	do { asm volatile("movl %%ebp, %0":"=r"(bp)); } while(0)
#define BP_PUT(val)	do { asm volatile("movl %0, %%ebp"::"r"(val)); } while(0)
#define SP(f)       ((unsigned long)(f)->esp0 + 5*4)
#define PC(f)       ((unsigned long)(f)->eip)
#include "switch_stack.c"

/* Breakpoint implementation; a simple linked list
 * (as I said, i386 support is not very sophisticated)
 */
static struct bpnt_ {
	struct bpnt_ *next;
	unsigned long addr;
	unsigned char byte;
} bpntTab[NUM_BPNTS] = {{0}};

static struct bpnt_ bpnts      = {0}; /* anchor el. */
static struct bpnt_ *bpntsFree = 0;

/* cf. gdb/i386-tdep.c, i387-tdep.c */

int
rtems_gdb_tgt_regoff(int regno, int *poff)
{
*poff = 0;
	if ( regno < 0 || regno > 31 )
		return -1;
	if ( regno < 16 ) {
		*poff += regno*4;
		return 4;
	}
	*poff += 16*4;
	regno -= 16;
	if ( regno < 8 ) {
		*poff += regno*8;
		return 8;
	}
	regno -= 8;
	*poff += 8*8 + regno*4;
	return 4;
}

#define EAX_OFF (0*4)
#define ECX_OFF (1*4)
#define EDX_OFF (2*4)
#define EBX_OFF (3*4)

#define ESP_OFF (4*4)
#define EBP_OFF (5*4)
#define ESI_OFF (6*4)
#define EDI_OFF (7*4)

#define EIP_OFF (8*4)
#define EFL_OFF (9*4)

#define CS_OFF (10*4)
#define SS_OFF (11*4)
#define DS_OFF (12*4)
#define ES_OFF (13*4)
#define FS_OFF (14*4)
#define GS_OFF (15*4)


#define GETSR(sr,buf) do { \
    asm volatile("pushl %%"#sr"; popl %0":"=r"(val)); \
    memcpy((buf)+sr##_OFF,&val,4); \
    } while (0)

#define PUTSR(sr,buf) do { \
    memcpy(&val,(buf)+sr##_OFF,4); \
    asm volatile("pushl %0; popl %%"#sr::"r"(val)); \
    } while (0)



/* map exception frame into register array (GDB layout) */
void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugMsg msg)
{
Thread_Control *tcb;
RtemsDebugFrame f = msg->frm;
int             deadbeef = 0xdeadbeef;
unsigned long	val;

	memset(buf, 0, NUMREGBYTES);

	if ( f ) {
		memcpy(buf + EAX_OFF, &f->eax, 4);
		memcpy(buf + ECX_OFF, &f->ecx, 4);
		memcpy(buf + EDX_OFF, &f->edx, 4);
		memcpy(buf + EBX_OFF, &f->ebx, 4);
		val = f->esp0 + 5*4; /* exception frame */
		memcpy(buf + ESP_OFF, &val,    4);
		memcpy(buf + EBP_OFF, &f->ebp, 4);
		memcpy(buf + ESI_OFF, &f->esi, 4);
		memcpy(buf + EDI_OFF, &f->edi, 4);

		memcpy(buf + EIP_OFF, &f->eip, 4);
		memcpy(buf + EFL_OFF, &f->eflags, 4);
	} else {
		memcpy(buf + EAX_OFF, &deadbeef, 4);
		memcpy(buf + ECX_OFF, &deadbeef, 4);
		memcpy(buf + EDX_OFF, &deadbeef, 4);
		memcpy(buf + EIP_OFF, &deadbeef, 4);
	}

	GETSR(CS,buf);
	if ( f ) assert( f->cs == val );
	GETSR(SS,buf);
	GETSR(DS,buf);
	GETSR(ES,buf);
	GETSR(FS,buf);
	GETSR(GS,buf);

	if ( (tcb = get_tcb(msg->tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			/* TODO: copy FP regs */
		}
		if (!f) {
			memcpy(buf + EBX_OFF, &tcb->Registers.ebx, 4);
			memcpy(buf + ESP_OFF, &tcb->Registers.esp, 4);
			memcpy(buf + EBP_OFF, &tcb->Registers.ebp, 4);
			memcpy(buf + ESI_OFF, &tcb->Registers.esi, 4);
			memcpy(buf + EDI_OFF, &tcb->Registers.edi, 4);
			memcpy(buf + EFL_OFF, &tcb->Registers.eflags, 4);
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
int            deadbeef = 0xdeadbeef, i;
unsigned long	val;

	if ( f ) {
		YPCMEM(buf + EAX_OFF, &f->eax, 4);
		YPCMEM(buf + ECX_OFF, &f->ecx, 4);
		YPCMEM(buf + EDX_OFF, &f->edx, 4);
		YPCMEM(buf + EBX_OFF, &f->ebx, 4);
		YPCMEM(buf + ESP_OFF, &val, 4);
		/* this value is not really written back to the hardware
		 * but used by the stack switcher
		 */
		f->esp0 = val - 5*4; /* exception frame */
		YPCMEM(buf + EBP_OFF, &f->ebp, 4);
		YPCMEM(buf + ESI_OFF, &f->esi, 4);
		YPCMEM(buf + EDI_OFF, &f->edi, 4);

		YPCMEM(buf + EIP_OFF, &f->eip, 4);
		YPCMEM(buf + EFL_OFF, &f->eflags, 4);

		YPCMEM(buf + CS_OFF, &f->cs, 4);

	} else {
		YPCMEM(buf + EAX_OFF, &deadbeef, 4);
		YPCMEM(buf + ECX_OFF, &deadbeef, 4);
		YPCMEM(buf + EDX_OFF, &deadbeef, 4);
		YPCMEM(buf + EIP_OFF, &deadbeef, 4);
	}

/*	PUTSR(CS,buf); */
	PUTSR(SS,buf);
	PUTSR(DS,buf);
	PUTSR(ES,buf);
	PUTSR(FS,buf);
	PUTSR(GS,buf);

	if ( (tcb = get_tcb(msg->tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			/* TODO: copy FP regs */
		}
		if (!f) {
			YPCMEM(buf + EBX_OFF, &tcb->Registers.ebx, 4);
			YPCMEM(buf + ESP_OFF, &tcb->Registers.esp, 4);
			YPCMEM(buf + EBP_OFF, &tcb->Registers.ebp, 4);
			YPCMEM(buf + ESI_OFF, &tcb->Registers.esi, 4);
			YPCMEM(buf + EDI_OFF, &tcb->Registers.edi, 4);
			YPCMEM(buf + EFL_OFF, &tcb->Registers.eflags, 4);
		}
		_Thread_Enable_dispatch();
	}
}

#undef YPCMEM

static void (*origHandler)()=0;

static void
exception_handler(RtemsDebugFrame f)
{
RtemsDebugMsgRec msg;

    if (   rtems_interrupt_is_in_progress()
	    || !_Thread_Executing 
		|| (RTEMS_SUCCESSFUL!=rtems_task_ident(RTEMS_SELF,RTEMS_LOCAL, &msg.tid)) ) {
		/* unable to deal with this situation */
		origHandler(f);
		return;
	}
printk("Task %x got exception %i, frame %x, sp %x, IP %x\n\n",
	msg.tid,f->idtIndex, f, f->esp0, f->eip);
printk("\n");

	/* the debugger should be able to handle its own exceptions */
	msg.frm = f;
    msg.sig = SIGHUP;

	switch ( f->idtIndex ) {
		case 0:  /* divide by zero  */
		case 4:  /* int overflow    */
		break;


		case 1:  /* debug exception */
		msg.sig = SIGTRAP;
		/* reset single step flag */
		f->eflags &= ~EFLAGS_TRAP;
		break;

		case 3:  /* breakpoint int3 */
		msg.sig = SIGCHLD;
		break;

		break;

		case 6:  /* invalid opcode  */
		msg.sig = SIGILL;
		break;

		case 7:  /* FPU not avail.  */
		case 8:  /* double fault    */
		case 9:  /* i387 seg overr. */
		case 16: /* fp error        */
		msg.sig = SIGFPE;
		break;

		case 5:  /* out-of-bounds   */
		case 10: /* Invalid TSS     */
		case 11: /* seg. not pres.  */
		case 12: /* stack except.   */
		case 13: /* general prot.   */
		case 14: /* page fault      */
		case 17: /* alignment check */
		msg.sig = SIGSEGV;
		break;

		case 2:  /* NMI             */
		case 18: /* machine check   */
		msg.sig = SIGBUS;
		break;

		default: break;
	}

	if ( msg.tid == rtems_gdb_tid ) {
		f->eip = (unsigned long)rtems_debug_handle_exception;
		f->eax = msg.sig;
        return;
	} else {

			switch_stack(&msg);
printk("Resumed from exception; contSig %i, sig %i, ESP 0x%08x PC 0x%08x EBP 0x%08x\n",
			msg.contSig, msg.sig, msg.frm->esp0, msg.frm->eip, msg.frm->ebp);

			if ( SIGCONT != msg.contSig ) {
				msg.frm->eflags |= EFLAGS_TRAP;
			}

		return;
	}

	origHandler(f);
}

int
rtems_debug_install_ehandler(int action)
{
int rval = 0, i;
rtems_unsigned32 flags;

	/* initialize breakpoint table */
	for ( i=0; i<NUM_BPNTS-1; i++ )
		bpntTab[i].next = bpntTab+i+1;
	bpntsFree = bpntTab;

	rtems_interrupt_disable(flags);
	if ( action ) {

		init_stack();

		/* install */
		if ( _currentExcHandler == exception_handler ) {
			rval = -1;
		} else {
			origHandler     = _currentExcHandler;
			_currentExcHandler = exception_handler;
		}
	} else {
		/* uninstall */
		if ( _currentExcHandler != exception_handler ) {
			rval = -1;
		} else {
			_currentExcHandler = origHandler;
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
rtems_gdb_tgt_set_pc(RtemsDebugMsg msg, unsigned long pc)
{
	assert( msg->frm );
	msg->frm->eip = pc;
}

unsigned long
rtems_gdb_tgt_get_pc(RtemsDebugMsg msg)
{
	assert( msg->frm );
	return msg->frm->eip;
}


static inline unsigned char
do_patch(volatile unsigned char *addr, unsigned char val)
{
unsigned char rval;
unsigned long flags;
	rtems_interrupt_disable(flags);
		rval  = *addr;
		*addr = val;
	rtems_interrupt_enable(flags);
	return rval;
}

int
rtems_gdb_tgt_insdel_breakpoint(int doins, int addr, int len)
{
struct bpnt_ *found, *prev;
unsigned char trap = INT3;

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
		unsigned char byte;
		if ( !bpntsFree )
			return -1;
		
		byte = do_patch((void*)addr, INT3);
		
		/* if we made it that far, we succeeded */
		found        = bpntsFree;
		bpntsFree    = bpntsFree->next;
		found->next  = bpnts.next;
		bpnts.next   = found;
		found->addr  = addr;
		found->byte  = byte;
	} else {
		do_patch((void*)addr, found->byte);
		/* if we made it that far, we succeeded */
		prev->next   = found->next;
		found->next  = bpntsFree;
		bpntsFree    = found;
		found->addr  = 0;
		found->byte  = 0;
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
		do_patch((void*)found->addr, found->byte);
		bpnts.next  = found->next;
		found->next = bpntsFree;
		bpntsFree   = found;
		found->addr = 0; 
		found->byte = 0;
	}
}

int
rtems_gdb_tgt_single_step(RtemsDebugMsg msg)
{
	return -1;
}
