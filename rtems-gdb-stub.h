/* $Id$ */
#ifndef RTEMS_GDB_STUB_H
#define RTEMS_GDB_STUB_H

/* Public interface header */

/* The daemon's TID */
extern volatile rtems_id rtems_gdb_tid;

#if !defined(DEBUGGING_ENABLED) && !defined(DEBUGGING_DISABLED)
#define DEBUGGING_ENABLED
#endif

/* Debugging; the 'rtems_remote_debug' variable can be set to a 'ORed' 
 *            bitset. Note: this var can be set using gdb itself :-)
 */
#define MSG_ERROR   (1<<0)	/* print error messages; on by default          */
#define MSG_INFO    (1<<1)	/* print informational messages; on by default  */
#define DEBUG_SCHED (1<<8)	/* log task switching, stopping, resuming, etc. */
#define DEBUG_SLIST (1<<9)	/* log what happens on the 'stopped' list       */
#define DEBUG_COMM  (1<<10)	/* log remcom proto messages to/from gdb        */
#define DEBUG_STACK (1<<11)	/* log stack switching related messages         */

extern volatile int rtems_remote_debug;

/* Macros for message logging; when using stdio (fprintf(stderr) or perror, ...)
 * the MSG_INFO / MSG_ERROR flags must be checked as there are scenarios
 * (daemon running in foreground on stdio) where all messages must be silenced.
 *
 */
#define INFMSG(fmt...)			\
	do { 						\
		if ( rtems_remote_debug & MSG_INFO ) \
			fprintf(stderr,fmt);\
	} while (0)

#define ERRMSG(fmt...)			\
	do { 						\
		if ( rtems_remote_debug & MSG_ERROR ) \
			fprintf(stderr,fmt);\
	} while (0)

/* from exception context */
#define KINFMSG(fmt...)			\
	do { 						\
		if ( rtems_remote_debug & MSG_INFO ) \
			printk(fmt);		\
	} while (0)

#define KERRMSG(fmt...)			\
	do { 						\
		if ( rtems_remote_debug & MSG_ERROR ) \
			printk(fmt);		\
	} while (0)

#ifdef DEBUGGING_ENABLED
/* debug messages check appropriate debug facility */
#define DBGMSG(facility, fmt...)	\
	do {							\
		if ( rtems_remote_debug & (facility) ) \
			fprintf(stderr,fmt);	\
	} while (0)

#define KDBGMSG(facility, fmt...)	\
	do {							\
		if ( rtems_remote_debug & (facility) ) \
			printk(fmt);	\
	} while (0)
#else
#define DBGMSG(facility, fmt...)	do {} while (0)
#define KDBGMSG(facility, fmt...)	do {} while (0)
#endif


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
