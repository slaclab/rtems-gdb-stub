/* $Id$ */
#ifndef RTEMS_GDB_STUB_H
#define RTEMS_GDB_STUB_H

#include "cdll.h"

extern volatile rtems_id rtems_gdb_tid;
extern volatile rtems_id rtems_gdb_break_tid;

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

/* announce that a frame-less thread should be single-stepped.
 * We need lowlevel support for this, e.g., to enable a
 * single step exception in the TCB
 *
 * Target may return nonzero to indicate that it doesn't know
 * how to deal with this.
 */
int
rtems_gdb_tgt_single_step(RtemsDebugMsg msg);

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

void rtems_gdb_breakpoint();

/* obtain the TCB of a thread.
 * NOTE that thread dispatching is enabled
 *      if this operation is successful
 *      (and disabled if unsuccessful)
 */

Thread_Control *
rtems_gdb_get_tcb_dispatch_off(rtems_id tid);

/* Debugging; the 'rtems_remote_debug' variable can be set to a 'ORed' 
 *            bitset. Note: this var can be set using gdb itself :-)
 */
#define DEBUG_SCHED (1<<0)	/* log task switching, stopping, resuming, etc. */
#define DEBUG_SLIST (1<<1)  /* log what happens on the 'stopped' list       */
#define DEBUG_COMM  (1<<2)  /* log remcom proto messages to/from gdb        */
#define DEBUG_STACK (1<<3)  /* log stack switching related messages         */

extern volatile int rtems_remote_debug;

/* Selective breakpoints: The GDB remote protocol has no provision to set
 *                        breakpoints on a pre-thread basis. You can set
 *                        this variable (e.g., from GDB) to a thread id
 *                        and (currently all) breakpoints are then only
 *                        active for the selected TID.
 */
extern volatile rtems_id rtems_gdb_break_tid;


#endif
