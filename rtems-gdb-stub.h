/* $Id$ */
#ifndef RTEMS_GDB_STUB_H
#define RTEMS_GDB_STUB_H

#define GDB_NET_EVENT RTEMS_EVENT_0
#define GDB_KILL_EVENT RTEMS_EVENT_1

extern volatile rtems_id rtems_gdb_q;
extern volatile rtems_id rtems_gdb_tid;

/* install / uninstall exception handler */
int
rtems_debug_install_ehandler(int action);

typedef struct RtemsDebugMsgRec_ {
	rtems_id	    tid;
	RtemsDebugFrame frm;
	int             sig;
	int				*contSig;
} RtemsDebugMsgRec, *RtemsDebugMsg;

void
rtems_gdb_tgt_f2r(unsigned char *buf, RtemsDebugFrame f, rtems_id tid);

void
rtems_gdb_tgt_r2f(RtemsDebugFrame f, rtems_id tid, unsigned char *buf);

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

void rtems_debug_breakpoint();
	
#endif
