/* $Id$ */
/* Target BSP specific gdb stub helpers for powerpc/shared & derived */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>

#include "rtems-gdb-stub-ppc-shared.h"

#include <libcpu/raw_exception.h> 
#include <libcpu/spr.h> 

#include <stdio.h>
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

#define GPR0_OFF  (0)
#define FPR0_OFF  (32*4)
#define PC___OFF  (32*4+32*8+4*0)
#define PS___OFF  (32*4+32*8+4*1)
#define CR___OFF  (32*4+32*8+4*2)
#define LR___OFF  (32*4+32*8+4*3)
#define CTR__OFF  (32*4+32*8+4*4)
#define XER__OFF  (32*4+32*8+4*6)
#define FPSCR_OFF (32*4+32*8+4*7)

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
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugFrame f, rtems_id tid)
{
Thread_Control *tcb;
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

	if ( (tcb = get_tcb(tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			memcpy(buf + FPR0_OFF, &fpc->f[0], 32*8 );
			memcpy(buf + FPSCR_OFF, &fpc->fpscr, 4);
		}
		if (!f) {
			Frame        sfr = (Frame)tcb->Registers.gpr1;
			unsigned lrdummy = 0xdeadbeef;
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
rtems_gdb_tgt_r2f(RtemsDebugFrame f, rtems_id tid, unsigned char *buf)
{
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

	if ( tid && (tcb = get_tcb(tid)) ) {
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

BSP_Exception_frame dummyFrame = {0};

static void (*origHandler)()=0;

static int
vec2sig(int exc_num)
{
	switch (exc_num) {
		default: break;
	}
	return -1; /* unknown */
}

static void
exception_handler(BSP_Exception_frame *f)
{
RtemsDebugMsgRec msg;
int				 contSig = -1;

	msg.contSig = &contSig;

    if (   rtems_interrupt_is_in_progress()
	    || !_Thread_Executing 
		|| (RTEMS_SUCCESSFUL!=rtems_task_ident(RTEMS_SELF,RTEMS_LOCAL,&msg.tid)) ) {
		/* unable to deal with this situation */
		origHandler(f);
		return;
	}
printk("Task %x got exception %i, frame %x, GPR1 %x\n",
	msg.tid,f->_EXC_number, f, f->GPR1);

	/* the debugger should be able to handle its own exceptions */
	msg.frm = f;
    msg.sig = -1;

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
			msg.sig = SIGILL;
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
			msg.sig = SIGTRAP;
		break;

		default: break;
	}
    if (f->EXC_SRR1 & MSR_FP) {
		/* thread dispatching is _not_ disabled at this point; hence
		 * we must make sure we have the FPU enabled...
		 */
		_write_MSR( _read_MSR() | MSR_FP );
		__asm__ __volatile__("isync");
	}
	if ( msg.tid == rtems_gdb_tid ) {
		origHandler(f);
		f->EXC_SRR0 = (unsigned long)rtems_debug_handle_exception;
		f->GPR3     = msg.sig;
        return;
	} else {
		rtems_message_queue_send(rtems_gdb_q, &msg, sizeof(msg));
		rtems_task_suspend(msg.tid);
	}

	origHandler(f);
}

int
rtems_debug_install_ehandler(int action)
{
int rval = 0;
rtems_unsigned32 flags;

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

