/* $Id$ */
/* Target BSP specific gdb stub helpers for powerpc/shared & derived */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/bspIo.h> /* printk */

#include "rtems-gdb-stub-i386.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>

#define get_tcb(tid) rtems_gdb_get_tcb_dispatch_off(tid)

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

/* map exception frame into register array (GDB layout) */
void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugMsg msg)
{
Thread_Control *tcb;
RtemsDebugFrame f = msg->frm;
int            deadbeef = 0xdeadbeef, i;
unsigned long	val;

	memset(buf, 0, NUMREGBYTES);

	if ( f ) {
		memcpy(buf + EAX_OFF, &f->eax, 4);
		memcpy(buf + ECX_OFF, &f->ecx, 4);
		memcpy(buf + EDX_OFF, &f->edx, 4);
		memcpy(buf + EBX_OFF, &f->ebx, 4);
		memcpy(buf + ESP_OFF, &f->esp0, 4);
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
	asm volatile ("pushl %%cs; popl %0"::"r"(val)); memcpy(buf + CS_OFF, &val, 4);
	if ( f ) assert( f->cs == val );
	asm volatile ("pushl %%ss; popl %0"::"r"(val)); memcpy(buf + SS_OFF, &val, 4);
	asm volatile ("pushl %%ds; popl %0"::"r"(val)); memcpy(buf + DS_OFF, &val, 4);
	asm volatile ("pushl %%es; popl %0"::"r"(val)); memcpy(buf + ES_OFF, &val, 4);
	asm volatile ("pushl %%fs; popl %0"::"r"(val)); memcpy(buf + FS_OFF, &val, 4);
	asm volatile ("pushl %%gs; popl %0"::"r"(val)); memcpy(buf + GS_OFF, &val, 4);


	if ( (tcb = get_tcb(msg->tid)) ) {
		Context_Control_fp *fpc = tcb->fp_context;
		if ( fpc ) {
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

void
rtems_gdb_tgt_r2f(RtemsDebugMsg msg, unsigned char *buf)
{
RtemsDebugFrame f = msg->frm;
Thread_Control *tcb = 0;
}

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
		default: break;
	}

	if ( msg.tid == rtems_gdb_tid ) {
		f->eip = (unsigned long)rtems_debug_handle_exception;
		f->eax = msg.sig;
        return;
	} else {

		BREAKPOINT();
printk("Resumed from exception; contSig %i, sig %i, ESP 0x%08x PC 0x%08x EBP 0x%08x\n",
			msg.contSig, msg.sig, msg.frm->esp0, msg.frm->eip, msg.frm->ebp);

		return;
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

int
rtems_gdb_tgt_insdel_breakpoint(int doins, int addr, int len)
{
return -1;
}

void
rtems_gdb_tgt_remove_all_bpnts()
{
}

int
rtems_gdb_tgt_single_step(RtemsDebugMsg msg)
{
	return -1;
}
