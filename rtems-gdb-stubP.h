/* $Id$ */
#ifndef RTEMS_GDB_STUB_PRIV_H
#define RTEMS_GDB_STUB_PRIV_H

/* private interface header */

#include "cdll.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <rtems.h>

#ifdef RTEMS_VERSION_ATLEAST
#define ISMINVERSION(ma,mi,re) RTEMS_VERSION_ATLEAST(ma,mi,re)
#else
#define ISMINVERSION(ma,mi,re) \
	(    __RTEMS_MAJOR__  > (ma)	\
	 || (__RTEMS_MAJOR__ == (ma) && __RTEMS_MINOR__  > (mi))	\
	 || (__RTEMS_MAJOR__ == (ma) && __RTEMS_MINOR__ == (mi) && __RTEMS_REVISION__ >= (re)) \
    )
#endif

#include "rtems-gdb-stub.h"
#include <signal.h>

/* TARGET ARCHITECTURE SPECIFIC ROUTINES; TO BE SUPPLIED BY
 * rtems-gdb-stub-xxxcpuxxx.c
 */

/* install / uninstall exception handler */
int
rtems_gdb_tgt_install_ehandler(int action);

typedef struct RtemsDebugMsgRec_ {
	CdllNodeRec				node;
	rtems_id	    		tid;
	RtemsDebugFrame 		frm;
	int             		sig;
	int						contSig;
} RtemsDebugMsgRec, *RtemsDebugMsg;

void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugMsg msg);

void
rtems_gdb_tgt_r2f(RtemsDebugMsg msg, unsigned char *buf);

/* set and read the PC from a (BSP) specific frame.
 * NOTE: is ILLEGAL to call these routines with a
 *       NULL frm field in msg.
 */

void
rtems_gdb_tgt_set_pc(RtemsDebugMsg msg, unsigned long pc);

unsigned long
rtems_gdb_tgt_get_pc(RtemsDebugMsg msg);

/* compute offset of a register (gdb number) into the
 * register memory block. Returns register size or -1
 * if regno invalid.
 */
int
rtems_gdb_tgt_regoff(int regno, int *poff);

/* insert / delete a breakpoint.
 * If the memory operation fails, the exception handler
 * should longjmp out of this routine.
 * 
 * RETURNS 0 on success, nonzero on failure (e.g., table full)
 */
int
rtems_gdb_tgt_insdel_breakpoint(int doins, int addr, int len);

void
rtems_gdb_tgt_remove_all_bpnts(void);

/* Announce that a frame-less thread should be single-stepped.
 * We need lowlevel support for this, e.g., to enable a
 * single step exception in the TCB
 *
 * Target may return nonzero to indicate that it doesn't know
 * how to deal with this.
 */
int
rtems_gdb_tgt_single_step(RtemsDebugMsg msg);

/* Dump exception frame contents for info to the console;
 * this routine is executed from exception context, i.e., it
 * must use 'printk'.
 */
void
rtems_gdb_tgt_dump_frame(RtemsDebugFrame frm);

/* Generic (architecture independent) routines */

/* this routine is called by the exception handler to notify
 * the stub daemon that a task has run into an exception.
 * the exception handler has to fill in the following fields:
 *
 *  'sig' : signal number (exception reason; SIGTRAP for breakpoint)
 *  'tid' : thread id
 *  'frm' : pointer to stack frame with registers context.
 * 
 * Note that the exception handling code must provide an
 * allocator/deallocator for the messages.
 *
 * It is legal for the exception handler to allocate the message
 * on the stack (easy for CPUs with an exception handler running
 * on the interrupted thread's stack).
 * 
 * Since the interrupted task is suspended by 
 * 'rtems_gdb_notify_and_suspend()', a message on the stack
 * exists until the task is resumed (e.g. after continuing
 * from a breakpoint). The caller will have filled-in the
 * 'contSig' field, in this case.
 *
 * RETURNS: 0 on success, nonzero on failure (e.g., during
 *          shutdown). The architecture dependent code should
 *          transfer control to the original exception handler
 *          if this routine returns a non-zero value.
 */
int rtems_gdb_notify_and_suspend(RtemsDebugMsg);

/* obtain the TCB of a thread.
 * NOTE that thread dispatching is enabled
 *      if this operation is successful
 *      (and disabled if unsuccessful)
 */

Thread_Control *
rtems_gdb_get_tcb_dispatch_off(rtems_id tid);

/* is this a crashed thread ? */
static inline int
rtems_gdb_thread_is_dead(RtemsDebugMsg m)
{
	return m->frm && SIGINT != m->sig && SIGTRAP != m->sig && SIGCHLD != m->sig;
}

#endif
