/* $Id$ */
#ifndef RTEMS_GDB_STUB_H
#define RTEMS_GDB_STUB_H

/* Public interface header */

/* The daemon's TID */
extern volatile rtems_id rtems_gdb_tid;

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

/* This function will generate a breakpoint exception. Note that you
 * must call rtems_gdb_start() first.
 */

void rtems_gdb_breakpoint();

/* start debugger thread with priority 'pri'
 * If no ttyName is passed (ttyName==0) socket
 * I/O is used
 */
int
rtems_gdb_start(int pri, char *ttyName);

/* stop debugger thread; use nonzero arg to override
 * thread safety warning / reject to perform the operation
 */
int
rtems_gdb_stop(int override);

#endif
