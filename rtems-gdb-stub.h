/* $Id$ */
#ifndef RTEMS_GDB_STUB_H
#define RTEMS_GDB_STUB_H

#include "cdll.h"

extern volatile rtems_id rtems_gdb_tid;

/* install / uninstall exception handler */
int
rtems_debug_install_ehandler(int action);

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

void
rtems_gdb_tgt_set_pc(RtemsDebugMsg msg, int pc);

/* compute offset of a register (gdb number) into the
 * register memory block. Returns register size or -1
 * if regno invalid.
 */
int
rtems_gdb_tgt_regoff(int regno, int *poff);

/* this routine is called after exception handler returns. It must
 * call LONGJMP
 */
void rtems_debug_handle_exception(int signo);

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
 * 'rtems_debug_notify_and_suspend()', a message on the stack
 * exists until the task is resumed (e.g. after continuing
 * from a breakpoint). The caller will have filled-in the
 * 'contSig' field, in this case.
 */
void rtems_debug_notify_and_suspend(RtemsDebugMsg);

void rtems_debug_breakpoint();
	
#endif
