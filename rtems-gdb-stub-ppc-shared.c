/* $Id$ */
/* Target BSP specific gdb stub helpers for powerpc/shared & derived */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>

#include "rtems-gdb-stub-ppc-shared.h"

#include <stdio.h>

static Thread_Control *
get_tcb(rtems_id tid)
{
Objects_Locations	loc;
Thread_Control		*tcb = 0;

	tcb = _Thread_Get(tid, &loc);

    if (OBJECTS_LOCAL!=loc || !tcb) {
		if (tcb)
			_Thread_Enable_dispatch();
        fprintf(stderr,"Id %x not found on local node\n",tid);
    }
	return tcb;
}

#define FPSCR_OFF (32*4+32*8+2*4+4*4)

/* map exception frame into register array (GDB layout) */
void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugFrame f, rtems_id tid)
{
Thread_Control *tcb = 0;

	memcpy(buf, &f->GPR0, 32*4);
	buf+=32*4;

	if ( tid && (tcb = get_tcb(tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			memcpy(buf, &fpc->f[0], 32*8 );
			memcpy(buf + (FPSCR_OFF - 32*4), &fpc->fpscr, 4);
		} else {
			tcb = 0;
		}
		_Thread_Enable_dispatch();
	}
	if ( !tcb )
		memset(buf, 0, 32*8);
	buf += 32*8;

	/* PC / PS */
	memcpy(buf, &f->EXC_SRR0, 4); buf += 4;
	memcpy(buf, &f->EXC_SRR1, 4); buf += 4;
	memcpy(buf, &f->EXC_CR,   4); buf += 4;
	memcpy(buf, &f->EXC_LR,   4); buf += 4;
	memcpy(buf, &f->EXC_CTR,  4); buf += 4;
	memcpy(buf, &f->EXC_XER,  4); buf += 4;
    buf += 4; /* fpscr done already */
}

void
rtems_gdb_tgt_r2f(RtemsDebugFrame f, rtems_id tid, unsigned char *buf)
{
Thread_Control *tcb;
	memcpy(&f->GPR0, buf, 32*4);
	buf+=32*4;

	if ( tid && (tcb = get_tcb(tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
			memcpy(&fpc->f[0], buf, 32*8 );
			memcpy(&fpc->fpscr,  0, sizeof(fpc->fpscr));
			memcpy(&fpc->fpscr,  buf + (FPSCR_OFF-32*4),4);
		} else {
			tcb = 0;
		}
		_Thread_Enable_dispatch();
	}
	buf += 32*8;

	/* PC / PS */
	memcpy(&f->EXC_SRR0, buf, 4); buf += 4;
	memcpy(&f->EXC_SRR1, buf, 4); buf += 4;
	memcpy(&f->EXC_CR,   buf, 4); buf += 4;
	memcpy(&f->EXC_LR,   buf, 4); buf += 4;
	memcpy(&f->EXC_CTR,  buf, 4); buf += 4;
	memcpy(&f->EXC_XER,  buf, 4); buf += 4;
	buf += 4; /* fpscr done already */
}

BSP_Exception_frame dummyFrame = {0};

static void (*origHandler)()=0;

static void
exception_handler(BSP_Exception_frame *f)
{

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
			origHandler            = globalExceptHdl;
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

