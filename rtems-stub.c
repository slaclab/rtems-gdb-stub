/* $Id$ */

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/error.h>
#include <rtems/bspIo.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#define HAVE_CEXP

#ifdef HAVE_CEXP
#include <cexp.h>
/* we do no locking - hope nobody messes with the
 * module list during a debugging session
 */
#include <cexpmodP.h>
#endif

#if defined(__PPC__)
#include "rtems-gdb-stub-ppc-shared.h"
#elif defined(__i386__)
#include "rtems-gdb-stub-i386.h"
#else
#error need target specific helper implementation
#endif

#define TID_ANY ((rtems_id)0)
#define TID_ALL ((rtems_id)-1)

static   FILE *rtems_gdb_strm = 0;

/* write a single character      */
static inline void putDebugChar(int ch)
{
	fputc(ch, rtems_gdb_strm);
}
/* read and return a single char */
static inline int getDebugChar()
{
	return fgetc(rtems_gdb_strm);
}

static inline void flushDebugChars()
{
	fflush(rtems_gdb_strm);
}

/* FORWARD DECLARATIONS */

static int
pendSomethingHappening(RtemsDebugMsg *, int, char*);

static int
resume_stopped_task(rtems_id tid, int sig);

#define BUFMAX      400		/* size of communication buffer; depends on NUMREGBYTES  */
#define EXTRABUFSZ	200     /* size of buffer for thread extra and other string info */

/* Debugging definitions */
#define STATIC

/* Configuration Defs    */
#define CTRLC  3
#define RTEMS_GDB_Q_LEN 200
#define RTEMS_GDB_PORT 4444

/* Adjust buffer sizes   */
#if (EXTRABUFSZ+15) > NUMREGBYTES
#  define CHRBUFSZ (EXTRABUFSZ+15)
#else
#  define CHRBUFSZ NUMREGBYTES
#endif

#if BUFMAX < 2*CHRBUFSZ + 100
#  undef  BUFMAX
#  define BUFMAX (2*CHRBUFSZ+100)
#endif

static volatile char initialized=0;

/* Include GPL code */

#include "crc32.c"

STATIC rtems_id gdb_pending_id = 0;

int semacount = 0;

static inline void SEMA_INC()
{
	semacount++;
}

static inline void SEMA_DEC()
{
unsigned long flags;
	rtems_interrupt_disable(flags);
	semacount--;
	rtems_interrupt_enable(flags);
}

#define DEBUG_SCHED (1<<0)
#define DEBUG_SLIST (1<<1)
#define DEBUG_COMM  (1<<2)

int     rtems_remote_debug = DEBUG_SCHED | DEBUG_SLIST;
/*  debug >  0 prints ill-formed commands in valid packets & checksum errors */ 

static const char hexchars[]="0123456789abcdef";

static rtems_id
thread_helper(char *nm, int pri, int stack, void (*fn)(rtems_task_argument), rtems_task_argument arg);

static RtemsDebugMsg
task_switch_to(RtemsDebugMsg m, rtems_id new_tid);

static int
task_resume(RtemsDebugMsg m, int sig);

static RtemsDebugMsg getFirstMsg(int);

/* list of threads that have stopped */
static CdllNodeRec anchor   = { &anchor, &anchor };

/* list of currently stopped threads */
static CdllNodeRec stopped  = { &stopped, &stopped};

/* list of 'dead' threads that we refuse to restart */
static CdllNodeRec cemetery = { &cemetery, &cemetery };

/* repository of free nodes */
static CdllNodeRec freeList = { &freeList, &freeList };

static RtemsDebugMsg
threadOnListBwd(CdllNode list, rtems_id tid)
{
CdllNode n;
	for ( n = list->p; n != list; n = n->p ) {
		if ( ((RtemsDebugMsg)n)->tid == tid )
			return (RtemsDebugMsg)n;
	}
	return 0;
}

STATIC inline RtemsDebugMsg
msgHeadDeQ(CdllNode list)
{
RtemsDebugMsg rval = (RtemsDebugMsg)cdll_dequeue_head(list);
	if ( &rval->node == list )
		return 0;
	assert( rval->node.p == rval->node.n && &rval->node == rval->node.p );
	return  rval;
}

STATIC RtemsDebugMsg
msgAlloc()
{
RtemsDebugMsg rval = msgHeadDeQ(&freeList);
	if ( !rval && (rval = calloc(1, sizeof(RtemsDebugMsgRec))) ) {
		cdll_init_el(&rval->node);	
	}
	assert( rval->node.p == rval->node.n && &rval->node == rval->node.p );
	return rval;
}

STATIC void
msgFree(RtemsDebugMsg msg)
{
	assert( msg->node.p == msg->node.n && &msg->node == msg->node.p );
	cdll_splerge_head(&freeList, (CdllNode)msg);
}

/************* jump buffer used for setjmp/longjmp **************************/
STATIC jmp_buf remcomEnv;

STATIC char remcomInBuffer[BUFMAX];
STATIC char remcomOutBuffer[BUFMAX];

#define GETCHAR() \
	  do { if ( (ch = getDebugChar()) < 0 ) { if (ch) perror("GETCHAR"); else fprintf(stderr,"GETCHAR ZERO\n"); return 0;} }  while (0)

#ifdef OBSOLETE_IO
#include "obsolete_io.c"
#  define hex2int hexToInt
#  define getpacket(buf) getpacket()
#else

STATIC int
hex(unsigned char ch)
{
int rval = toupper(ch);
	return rval > '9' ? rval-'A'+10 : rval-'0';
}

/* scan for the sequence $<data>#<checksum>     */
STATIC unsigned char *
getpacket(unsigned char *buf)
{
unsigned char	chks, xchks;
int				n,ch = 0;

	goto synchronize;

	do {

		putDebugChar('-');
		flushDebugChars();
		if ( rtems_remote_debug ) {
			fprintf(stderr,"Checksum mismatch: counted %x, xmit-sum is %x, string %s\n",
					chks, xchks, buf);
		}

synchronize:

		/* skip till we detect a lead-char */
		while ( '$' != ch ) {
			GETCHAR();
		}

		GETCHAR();

		for ( n = chks = 0; '#'!=ch; ) {
			if ( '$' == ch || n >= BUFMAX-1 ) {
				/* start over */
				goto synchronize;
			} else {
				buf[n++] = ch;
				chks  += ch;
			}
			GETCHAR();
		}
		buf[n] = 0;

		GETCHAR();
		xchks = hex(ch);
		GETCHAR();
		xchks = (xchks<<4) + hex(ch);

	} while (xchks != chks);

	putDebugChar('+');
	if ( ':' == buf[2] ) {
		/* sequence; echo seq. id */
		putDebugChar(buf[0]);
		putDebugChar(buf[1]);
		buf += 3;
	}
	flushDebugChars();
	return buf;
}

/* send the packet in NULL terminated buffer. */
STATIC int
putpacket(char *buf)
{
register unsigned char chks, *pch;
register int           i;
	do {
		putDebugChar('$');
		for ( chks=0, pch=buf; *pch; pch++ ) {
			putDebugChar(*pch);
			chks += *pch;
		}
		putDebugChar('#');
		putDebugChar(hexchars[chks>>4]);
		putDebugChar(hexchars[chks & 0xf]);
		flushDebugChars();
		if ( rtems_remote_debug & DEBUG_COMM ) {
			fprintf(stderr,"Putting packet: %s\n",buf);
		}
		i = getDebugChar();
	} while ( i > 0 && '+' != i );
	if ( rtems_remote_debug & DEBUG_COMM)
		fprintf(stderr,"PUTPACK return i %i\n",i);
	return i<=0;	
}

/* Convert binary data to null terminated hex string;
   return pointer to terminating NULL */

STATIC char *
mem2hex(char *mem, char *buf, int len)
{
register unsigned char ch;
	while (len-- >= 0) {
		ch = *mem++;
		*buf++ = hexchars[ch >>  4];
		*buf++ = hexchars[ch & 0xf];
	}
	*buf = 0;
	return buf;
}

/* Convert hex string to binary; return a pointer to the byte
 * after the last one written
 */

STATIC char *
hex2mem(char *buf, char *mem, int len)
{
	while (len--) {
		*mem    = (hex(*buf++) << 4);
		*mem++ +=  hex(*buf++);
	}
	return mem;
}

/* Convert hex string into number; return number of chars converted */
STATIC int
hex2int(char **ppch, int *pval)
{
register int n,val;
register unsigned char ch;

	for (n=val=0; (ch=**ppch, isxdigit(ch)); n++, (*ppch)++) {
		val = (val<<4) + hex(ch);
	}
	*pval = val;
	return n;
}

#endif /* OBSOLETE_IO */

/* integer to BE hex; buffer must be large enough */
STATIC char *
int2hex(int i, char *buf)
{
register int j = 2*sizeof(i);

	if ( i< 0 ) {
		*buf++='-';
		i = -i;
	}
	buf[j--]=0;
	do {
		buf[j--] = hexchars[i&0xf];
		i>>=4;
	} while ( j>=0 );
	return buf+2*sizeof(i);
}

STATIC void
debug_error (char *format, char *parm)
{
  if (rtems_remote_debug)
    fprintf (stderr, format, parm);
}

volatile rtems_id  rtems_gdb_tid       = 0;
volatile int       rtems_gdb_sd        = -1;
volatile rtems_id  rtems_gdb_break_tid = 0;

STATIC RtemsDebugMsg	theDummy = 0;
STATIC unsigned long    dummy_frame_pc;

static volatile int      waiting = 0;

static void sowake(struct socket *so, caddr_t arg)
{
rtems_status_code sc;

	if ( waiting ) {
		sc = rtems_semaphore_flush(gdb_pending_id);
	}

}

static int resume_stopped_task(rtems_id tid, int sig)
{
RtemsDebugMsg m;
int rval, do_free;
	if ( tid ) {
		m = threadOnListBwd(&stopped, tid);
		if ( m ) {
			if ( rtems_remote_debug & DEBUG_SLIST )
				fprintf(stderr,"stopped: removed %x\n", m->tid);
			cdll_remove_el(&m->node);
			/* see comment below why we use 'do_free' */
			do_free = (m->frm == 0);
			rval = task_resume(m,sig);
			if (do_free) {
				m->tid = 0;
				msgFree(m);
			}
		} else {
			fprintf(stderr,"Unable to resume 0x%08x -- not found on stopped list\n", tid);
			rval = -1;
		}
	} else {
		rval = 0;
		/* release all currently stopped threads */
		while ( (m=msgHeadDeQ(&stopped)) ) {
			if ( rtems_remote_debug & DEBUG_SLIST )
				fprintf(stderr,"stopped: removed %x from head\n", m->tid);
			do_free = (m->frm == 0);
			/* cannot access 'msg' after resuming. If it
			 * was a 'real', i.e., non-frameless message then
			 * it lived on the stack of the to-be resumed
			 * thread.
			 */
			if ( task_resume(m, sig) ) {
				if ( rtems_remote_debug & DEBUG_SCHED )
					fprintf(stderr,"Task resume %x FAILURE\n",m->tid);
				rval = -1;
			}
			if ( do_free ) {
				m->tid = 0;
				msgFree(m);
			}
		}
	}
	return rval;
}

static void detach_all_tasks()
{
RtemsDebugMsg msg;

	rtems_gdb_tgt_remove_all_bpnts();

	/* detach all tasks */

	/* collect all pending tasks */
	while ( (msg=getFirstMsg(0)) )
		;

	/* and resume everything */
	resume_stopped_task(0, SIGCONT);

	rtems_gdb_break_tid = 0;
}

static void cleanup_connection()
{
struct sockwakeup wkup = {0};

	if ( rtems_remote_debug & DEBUG_SCHED )
		printf("Releasing connection\n");

	detach_all_tasks();

	/* make sure the callback is removed */
    setsockopt(fileno(rtems_gdb_strm), SOL_SOCKET, SO_RCVWAKEUP, &wkup, sizeof(wkup));
	fclose( rtems_gdb_strm );
	rtems_gdb_strm = 0;
}

static int
havestate(RtemsDebugMsg m)
{
	if ( TID_ANY == m->tid || TID_ALL == m->tid ) {
		strcpy(remcomOutBuffer,"E16");
		return 0;
	}
	return 1;
}

STATIC rtems_id *
get_tid_tab(rtems_id *t)
{
int                 max, cur, i, api;
Objects_Information *info;
Objects_Control		*c;
	/* count slots */
	{
again:
		/* get current estimate */
		for ( max=0, api=0; api<=OBJECTS_APIS_LAST; api++ ) {
			Objects_Information **apiinfo = _Objects_Information_table[api];
			if ( apiinfo && (info = apiinfo[1/* thread class for all APIs*/] ) )
				max += info->maximum;
		}
		t = realloc(t, sizeof(rtems_id)*(max+1));

		if ( t ) {
			cur = 0;
			_Thread_Disable_dispatch();
			for ( api=0; api<=OBJECTS_APIS_LAST; api++ ) {
				Objects_Information **apiinfo = _Objects_Information_table[api];
				if ( !apiinfo
                    || !(info = apiinfo[1/* thread class for all APIs*/] )
					|| !info->local_table )
					continue;
				for ( i=1; i<=info->maximum; i++ ) {
					if (!(c=info->local_table[i]))
						continue;
					t[cur++] = c->id;
					if ( cur >= max ) {
						/* table was extended since we determined the maximum; try again */
						_Thread_Enable_dispatch();
						goto again;
					}
				}
			}
			_Thread_Enable_dispatch();
			t[cur]=0;
		}
	}
	return t;
}

static void
dummy_thread(rtems_task_argument arg)
{
	while (1) {
#ifdef DUMMY_SUSPENDED
		rtems_task_suspend(RTEMS_SELF);
#else
		BREAKPOINT();
#endif
		sleep(1);
	}
}

static  RtemsDebugMsgRec  currentEl = {{&currentEl.node,&currentEl.node},0};

static  rtems_id        dummy_tid = 0;

static int unAttachedCmd(int ch)
{
	return 'H' == ch || 'm'==ch || 'd' == ch || 'D' == ch
           || 'q' == ch;
}

static int compileThreadExtraInfo(char *extrabuf, rtems_id tid)
{
Thread_Control    *thr;
Objects_Locations l;
States_Control    state = 0xffff;
int               pri   = 0, i = 0;

	memset(extrabuf,0,EXTRABUFSZ);
	if ( (thr=_Thread_Get( tid, &l )) ) {
		if ( OBJECTS_LOCAL == l ) {
			Objects_Information *oi;
			oi = _Objects_Get_information( tid );
			*extrabuf = '\'';
			if ( oi->is_string ) {
				if ( oi->name_length < EXTRABUFSZ ) {
					_Objects_Copy_name_string( thr->Object.name, extrabuf + 1  );
				} else {
					strcpy( extrabuf + 1, "NAME TOO LONG" ); 
				}
			} else {
				_Objects_Copy_name_raw( &thr->Object.name, extrabuf + 1, oi->name_length );
			}
			state = thr->current_state;
			pri   = thr->real_priority;
		}
		_Thread_Enable_dispatch();
		if ( OBJECTS_LOCAL != l )
			return 0;
		i = strlen(extrabuf);
		extrabuf[i++]='\'';
		while (i<8)
			extrabuf[i++]=' ';
		i+=snprintf(extrabuf+i,EXTRABUFSZ-i,"PRI: %3d STATE:", pri);
		state = state & STATES_ALL_SET;
		if ( i<EXTRABUFSZ ) {
			if ( STATES_READY == state)
				i+=sprintf(extrabuf+i," ready");
			else {
			if ( STATES_DORMANT   & state && i < EXTRABUFSZ ) {
				i+=sprintf(extrabuf+i," dorm");
				state &= ~STATES_DORMANT;
			}
			if ( STATES_SUSPENDED & state && i < EXTRABUFSZ ) {
				i+=sprintf(extrabuf+i," susp");
				state &= ~STATES_SUSPENDED;
			}
			if ( STATES_TRANSIENT & state && i < EXTRABUFSZ ) {
				i+=sprintf(extrabuf+i," trans");
				state &= ~STATES_TRANSIENT;
			}
			if ( STATES_BLOCKED & state && i < EXTRABUFSZ ) {
				i+=sprintf(extrabuf+i," BLOCKED - ");
				if ( STATES_DELAYING  & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," delyd");
				if ( STATES_INTERRUPTIBLE_BY_SIGNAL  & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," interruptible");
				if ( STATES_WAITING_FOR_TIME & state && i < EXTRABUFSZ )
						i+=sprintf(extrabuf+i," time");
			if ( STATES_WAITING_FOR_BUFFER & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," buf");
				if ( STATES_WAITING_FOR_SEGMENT & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," seg");
				if ( STATES_WAITING_FOR_MESSAGE & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," msg");
				if ( STATES_WAITING_FOR_EVENT & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," evt");
				if ( STATES_WAITING_FOR_SEMAPHORE & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," sem");
				if ( STATES_WAITING_FOR_MUTEX & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," mtx");
				if ( STATES_WAITING_FOR_CONDITION_VARIABLE & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," cndv");
				if ( STATES_WAITING_FOR_JOIN_AT_EXIT & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," join");
				if ( STATES_WAITING_FOR_RPC_REPLY & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," rpc");
				if ( STATES_WAITING_FOR_PERIOD & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," perio");
				if ( STATES_WAITING_FOR_SIGNAL & state && i < EXTRABUFSZ )
					i+=sprintf(extrabuf+i," sig");
				state &= ~STATES_BLOCKED;
			}
			}
			if ( state && i < EXTRABUFSZ ) {
				i+=snprintf(extrabuf+i, EXTRABUFSZ-i, "?? (0x%x)", state);
			}
		}
	}
	return i;
}
/*
 * This function does all command processing for interfacing to gdb.
 */
STATIC void
rtems_gdb_daemon (rtems_task_argument arg)
{
  char              *ptr, *pto;
  const char        *pfrom;
  char              *chrbuf = 0;
  int               sd,regno,i,j;
  RtemsDebugMsg     current = 0;
  rtems_status_code sc;
  rtems_id          *tid_tab = calloc(1,sizeof(rtems_id)), tid, cont_tid;
  int               tidx = 0;
  int               ehandler_installed=0;
  CexpModule		mod   = 0;
  CexpSym           *psectsyms = 0;
  int				addr,len;
  /* startup / initialization */
  {
    if ( RTEMS_SUCCESSFUL !=
		 ( sc = rtems_semaphore_create(
					rtems_build_name( 'g','d','b','s' ),
					0,
					RTEMS_FIFO | RTEMS_COUNTING_SEMAPHORE,
					0,
					&gdb_pending_id ) ) ) {
		gdb_pending_id = 0;
		rtems_error( sc, "GDBd: unable to create semaphore" );
		goto cleanup;
	}
	if ( !(chrbuf = malloc(CHRBUFSZ)) ) {
		fprintf(stderr,"no memory\n");
		goto cleanup;
	}

    /* create socket */
    rtems_gdb_sd = socket(PF_INET, SOCK_STREAM, 0);
	if ( rtems_gdb_sd < 0 ) {
		perror("GDB daemon: socket");
		goto cleanup;
	}
	{
    int                arg = 1;
    struct sockaddr_in srv; 

      setsockopt(rtems_gdb_sd, SOL_SOCKET, SO_KEEPALIVE, &arg, sizeof(arg));
      setsockopt(rtems_gdb_sd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg));

      memset(&srv, 0, sizeof(srv));
      srv.sin_family = AF_INET;
      srv.sin_port   = htons(RTEMS_GDB_PORT);
      arg            = sizeof(srv);
      if ( bind(rtems_gdb_sd,(struct sockaddr *)&srv,arg)<0 ) {
        perror("GDB daemon: bind");
		goto cleanup;
      };
    }
	if ( listen(rtems_gdb_sd, 1) ) {
		perror("GDB daemon: listen");
		goto cleanup;
	}
	if (rtems_debug_install_ehandler(1))
		goto cleanup;
	ehandler_installed=1;
	if ( !(dummy_tid = thread_helper("GDBh", 200, 20000+RTEMS_MINIMUM_STACK_SIZE, dummy_thread, 0)) )
		goto cleanup;
  }

  initialized = 1;

  while (initialized) {

	/* synchronize with dummy task */
	if ( !theDummy ) {
		getFirstMsg(1);
		assert( theDummy );
	}
	dummy_frame_pc = rtems_gdb_tgt_get_pc( theDummy );
#ifndef ONETHREAD_TEST
	current = theDummy;
#else
	current = 0;
#endif

	{
	struct sockaddr_in a;
    struct sockwakeup  wkup;
	int                a_s = sizeof(a);
	if ( (sd = accept(rtems_gdb_sd, (struct sockaddr *)&a, &a_s)) < 0 ) {
		perror("GDB daemon: accept");
		goto cleanup;
	}
    wkup.sw_pfn = sowake;
    wkup.sw_arg = (caddr_t)0;
    setsockopt(sd, SOL_SOCKET, SO_RCVWAKEUP, &wkup, sizeof(wkup));
	}
	if ( !(rtems_gdb_strm = fdopen(sd, "r+")) ) {
		perror("GDB daemon: unable to open stream");
		close(sd);
		goto cleanup;
	}

	cont_tid = 0;

	while ( (ptr = getpacket(remcomInBuffer)) ) {

    remcomOutBuffer[0] = 0;

	if ( rtems_remote_debug & DEBUG_COMM ) {
		printf("Got packet '%s' \n", ptr);
	}

	if ( current || unAttachedCmd(*ptr) ) {

    switch (*ptr++)
	{
	default:
	  remcomOutBuffer[0] = 0;
	  break;

	case '?':
	  sprintf(remcomOutBuffer,"T%02xthread:%08x;",current->sig, current->tid);
	  break;

	case 'd':
	  rtems_remote_debug = !(rtems_remote_debug);	/* toggle debug flag */
	  break;

		/* Detach */
	case 'D':
      strcpy(remcomOutBuffer,"OK");
#ifndef ONETHREAD_TEST
	  detach_all_tasks();
	  current = 0;
	  rtems_gdb_break_tid = 0;
#else
	  goto cleanup_connection();
#endif
	break;

	case 'g':		/* read registers */
	  if (!havestate(current))
		break;
	  rtems_gdb_tgt_f2r(chrbuf, current);
	  mem2hex ((char *) chrbuf, remcomOutBuffer, NUMREGBYTES);
	  break;

	case 'G':		/* set registers and return OK */
	  if (!havestate(current))
		break;
	  hex2mem (ptr, (char *) chrbuf, NUMREGBYTES);
	  rtems_gdb_tgt_r2f(current, chrbuf);
	  strcpy (remcomOutBuffer, "OK");
	  break;

		/* H[g|c]<tid> set current thread --
		 *
		 * NOTE: Hg STOPS and 'attaches' the target thread
		 */
    case 'H':
      {
		tid = strtol(ptr+1,0,16);
		if ( rtems_remote_debug & DEBUG_SCHED ) {
			printf("New 'H%c' thread id set: 0x%08x\n",*ptr,tid);
		}
#ifndef ONETHREAD_TEST
	  	if ( 'c' == *ptr ) {
			/* We actually have slightly different semantics.
			 * In our case, this TID tells us whether we break
			 * on this tid only or on any arbitrary one
			 */
			/* NOTE NOTE: This currently does NOT work -- GDB inserts
			rtems_gdb_break_tid = (TID_ALL == tid || TID_ANY == tid) ? 0 : tid;
			 *            breakpoints prior to sending the thread id :-(
			 *            maybe we should globally enable breakpoints
			 *            only when we 'continue' or 'step'
			 */
			cont_tid = tid;
	  	} else if ( 'g' == *ptr ) {
			if ( (TID_ALL == tid || TID_ANY == tid) )
				tid = current->tid ? current->tid : dummy_tid;
			else if ( rtems_gdb_tid == tid )
				tid = dummy_tid;
			if ( current->tid == tid )
				break;
			current = task_switch_to(current, tid);
	  	}
#else
		if ( rtems_gdb_break_tid && tid != rtems_gdb_break_tid ) {
			strcpy(remcomOutBuffer,"E0D");
		} else if ( !current ) {
			/* "attach" */
			if ( tid ) {
				rtems_gdb_break_tid = tid;
				current = task_switch_to( 0, tid );
			} else {
				/* wait for target */
				if ( pendSomethingHappening(&current, tid, remcomOutBuffer) < 0 ) {
					/* daemon killed */
					goto release_connection;
				}

			}
		}
#endif
	  }
    break;

	  /* m<addr>,<len>  --  read <len> bytes at <addr> */
	case 'm':
		if (   !hex2int(&ptr, &addr)
			|| ',' != *ptr++
			|| !hex2int(&ptr, &len) ) {
			strcpy (remcomOutBuffer, "E01");
			break;
		}
		if (setjmp (remcomEnv) == 0) {
			/* Try to read */
			mem2hex ((char *) addr, remcomOutBuffer, len);
		} else {
			strcpy (remcomOutBuffer, "E03");
			debug_error ("%s\n","bus error");
	    }
	break;

	  /* M<addr>,<len>:<xx>  -- write <len> bytes (<xx>) to address <addr>, return OK */
	case 'M':
		if (   !hex2int(&ptr, &addr)
			|| ',' != *ptr++
			|| !hex2int(&ptr, &len)
			|| ':' != *ptr++ ) {
			strcpy (remcomOutBuffer, "E02");
			break;
		}
		if (setjmp (remcomEnv) == 0) {
			/* Try to write */
			hex2mem (ptr, (char *) addr, len);
			strcpy (remcomOutBuffer, "OK");
		} else {
	      strcpy (remcomOutBuffer, "E03");
	      debug_error ("%s\n","bus error");
	    }

	  break;

	case 's': /* trace */
	case 'c':
		{
		int contsig = 's' == *(ptr-1) ? SIGTRAP : SIGCONT;

		if ( hex2int(&ptr, &i) ) { /* optional addr arg */
			if ( current ) {
				if ( !current->frm ) {
					/* refuse if we don't have a 'real' frame */
					strcpy(remcomOutBuffer,"E0D");
					break;
				}
				rtems_gdb_tgt_set_pc(current, i);
			}
		}

		if ( current ) {
			tid  = current->tid;

			/* we're only want to know if resuming the current thread was successful */
			if ( !cont_tid || cont_tid == tid )
				i = resume_stopped_task( tid, contsig );
			else
				i = -1;

			if ( cont_tid != tid )
				resume_stopped_task( cont_tid, contsig );

		} else {
			i   = 0;
			tid = rtems_gdb_break_tid;
		}
		}

		if ( -2 == i ) {
			/* target doesn't know how to start single-stepping on
			 * a suspended thread (which has no real frame)
			 */
			strcpy(remcomOutBuffer,"E0D");
			break;
		} else if ( 0 == i )
			current = 0;

		if ( pendSomethingHappening(&current, tid, remcomOutBuffer) < 0 )
			/* daemon killed */
			goto release_connection;

	break;

		/* P<regno>=<val>  -- set register # <regno> to <val> */
	case 'P':
	  strcpy(remcomOutBuffer,"E16");
	  if (   !havestate(current)
          || !hex2int(&ptr, &regno)
          || '=' != *ptr++
		  || (i = rtems_gdb_tgt_regoff(regno, &j)) < 0 )
		break;
		
	  rtems_gdb_tgt_f2r((char*)chrbuf,current);
	  hex2mem (ptr, ((char*)chrbuf) + j, i);
	  rtems_gdb_tgt_r2f(current, chrbuf);
	  strcpy (remcomOutBuffer, "OK");
	  break;

		/* qXXX; various query packets, including our Cexp extensions */
	case 'q':
      if ( !strcmp(ptr,"Offsets") ) {
		/* ignore; GDB should use values from executable file */
	  } else if ( !strncmp(ptr,"CRC:",4) ) {
		ptr+=4;
		if ( !hex2int(&ptr,&addr) || ','!=*ptr++ || !hex2int(&ptr,&len) ) {
			strcpy(remcomOutBuffer,"E0D");
		} else {
			if ( 0 == setjmp(remcomEnv) ) {
				/* try to compute crc */
				sprintf(remcomOutBuffer,"C%x",(unsigned)crc32((char*)addr, len, -1));
			} else {
	      		strcpy (remcomOutBuffer, "E03");
	      		debug_error ("%s\n","bus error");
			}
		}
	  } else if ( !strcmp(ptr+1,"ThreadInfo") ) {
		if ( 'f' == *ptr ) {
			tidx = 0;
			/* TODO get thread snapshot */
			tid_tab = get_tid_tab(tid_tab);
		}
		pto    = remcomOutBuffer;
		if ( !tid_tab[tidx] ) {
			strcpy(pto,"l");
		} else {
			while ( tid_tab[tidx] && pto < remcomOutBuffer + sizeof(remcomOutBuffer) - 20 ) {
				*pto++ = ',';
				pto    = int2hex(tid_tab[tidx++], pto);
			}
			*pto = 0;
			remcomOutBuffer[0]='m';
		}
	  } else if ( !strncmp(ptr,"ThreadExtraInfo",15) ) {
		ptr+=15;
		if ( ','== *ptr ) {
			tid = strtol(++ptr,0,16);
			i = compileThreadExtraInfo(chrbuf, tid);
			if (*chrbuf)
	  			mem2hex (chrbuf, remcomOutBuffer, i+1);
		}
	  } else if ( !strcmp(ptr+1,"CexpFileList") ) {
	    if ( 'f' == *ptr ) {
			mod = cexpSystemModule->next;
		}
		if ( mod ) {
			pto    = remcomOutBuffer;
			*pto++ = 'm';
			pto    = int2hex(mod->text_vma, pto); 
			*pto++ = ',';
			if ( !(pfrom = strrchr(mod->name,'/')) )
				pfrom = mod->name;
			else
				pfrom++;
			if ( strlen(pfrom) > BUFMAX - 15 )
				strcpy(remcomOutBuffer,"E24");
			else
				strcpy(pto,pfrom);
			mod = mod->next;
		} else {
			strcpy(remcomOutBuffer,"l");
		}
#define SECTLIST_STR "CexpSectionList"
	  } else if ( !strncmp(ptr+1,SECTLIST_STR,strlen(SECTLIST_STR)) ) {
	    if ( 'f' == *ptr ) {
			ptr+=1+strlen(SECTLIST_STR);
			psectsyms = 0;
			if ( ',' != *ptr || !*(ptr+1) ) {
				strcpy(remcomOutBuffer,"E16");
			} else {
				mod = cexpModuleFindByName(++ptr, CEXP_FILE_QUIET);
				if ( !mod ) {
					strcpy(remcomOutBuffer,"E02");
					break;
				} else {
					psectsyms = mod->section_syms;
					mod = 0;
				}
			}
		}
		if ( psectsyms && *psectsyms ) {
			pto    = remcomOutBuffer;
			*pto++ = 'm';
			pto    = int2hex((int)(*psectsyms)->value.ptv, pto); 
			*pto++ = ',';
			pfrom  = (*psectsyms)->name;
			if ( strlen(pfrom) > BUFMAX - 15 )
				strcpy(remcomOutBuffer,"E24");
			else
				strcpy(pto,pfrom);
			psectsyms++;
		} else {
			strcpy(remcomOutBuffer,"l");
		}
	  }

	  break;

		/* T<tid>             -- is thread <tid> alive? */
	  case 'T':
		{
		rtems_id tid;
			strcpy(remcomOutBuffer,"E01");
			tid = strtol(ptr,0,16);
			/* use a cheap call to find out if this is still alive ... */
			sc = rtems_task_is_suspended(tid);
			if ( RTEMS_SUCCESSFUL == sc || RTEMS_ALREADY_SUSPENDED == sc )
				strcpy(remcomOutBuffer,"OK");
		}	
	  break;

		/* X<addr>,<len>:<bb>  -- binary memory write */
	  case 'X':
		if (   !hex2int(&ptr,&addr)
			|| ',' != *ptr++
			|| !hex2int(&ptr,&len)
			|| ':' != *ptr++ ) {
			break; /* protocol error */
		}
		if ( 0 == setjmp(remcomEnv) ) {
			for ( i=0; i<len; i++ ) {
				if ( 0x7d == *ptr )
					*++ptr ^= 0x20;
				((volatile char*)addr)[i] = *((volatile char*)ptr)++;
			}
			strcpy(remcomOutBuffer,"OK");
		} else {
	      	strcpy (remcomOutBuffer, "E03");
	      	debug_error ("%s\n","bus error");
		}
	  break;

		/* z<type>,<addr>,<len>   -- remove/insert <type> breakpoint at <addr> */
	  case 'z':
	  case 'Z':
		{
		char *op = ptr++-1;
		if (   ',' != *ptr++ || !hex2int(&ptr,&addr)
            || ',' != *ptr++ || !hex2int(&ptr,&len) 
			)
		break;

		switch ( op[1] ) {
			case '0':
			/* software breakpoint */
			if ( 0 == setjmp(remcomEnv) ) {
				/* try to write breakpoint */
				if ( rtems_gdb_tgt_insdel_breakpoint('Z'==op[0],addr,len) ) {
					strcpy(remcomOutBuffer,"E16");
				} else {
					strcpy(remcomOutBuffer,"OK");
				}
			} else {
	      		strcpy (remcomOutBuffer, "E03");
	      		debug_error ("%s\n","bus error");
			}
			break;
			default:	
				strcpy (remcomOutBuffer, "E16");
			break;
		}
		}
	  break;

	}			/* switch */
	}

      /* reply to the request */
      if (putpacket (remcomOutBuffer))
		goto release_connection;
  } /* interpreter loop */
release_connection:
  /* make sure attached thread continues */
  cleanup_connection();

  }

/* shutdown */
cleanup:
  if ( gdb_pending_id )
	rtems_semaphore_delete( gdb_pending_id );
  if (dummy_tid)
  	rtems_task_delete(dummy_tid);
  if ( ehandler_installed ) {
	rtems_debug_install_ehandler(0);
  }
  if ( rtems_gdb_strm ) {
	fclose(rtems_gdb_strm);
	rtems_gdb_strm = 0;
  }
  if ( 0 <= rtems_gdb_sd ) {
    close(rtems_gdb_sd);
  }
  free( chrbuf );
  free( tid_tab );

  rtems_gdb_tid=0;
  rtems_task_delete(RTEMS_SELF);
}

/* This function will generate a breakpoint exception.  It is used at the
   beginning of a program to sync up with a debugger and can be used
   otherwise as a quick means to stop program execution and "break" into
   the debugger. */

void
rtems_debug_breakpoint ()
{
  if (initialized)
    BREAKPOINT ();
}

void rtems_debug_handle_exception(int signo)
{
	longjmp(remcomEnv,1);
}

static rtems_id
thread_helper(char *nm, int pri, int stack, void (*fn)(rtems_task_argument), rtems_task_argument arg)
{
char              buf[4];
rtems_status_code sc;
rtems_id          rval = 0;


	if ( 0==pri )
		pri = 100;

	if ( 0==stack )
		stack = RTEMS_MINIMUM_STACK_SIZE;

	memset(buf,'x',sizeof(buf));
	if (nm)
		strncpy(buf,nm,4);
	else
		nm="<NULL>";

	sc = rtems_task_create(	
			rtems_build_name(buf[0],buf[1],buf[2],buf[3]),
			pri,
			stack,
			RTEMS_DEFAULT_MODES,
			RTEMS_LOCAL | RTEMS_FLOATING_POINT,
			&rval);
	if ( RTEMS_SUCCESSFUL != sc ) {
		rtems_error(sc, "Creating task '%s'",nm);
		goto cleanup;
	}

	sc = rtems_task_start(rval, fn, arg);
	if ( RTEMS_SUCCESSFUL != sc ) {
		rtems_error(sc, "Starting task '%s'",nm);
		rtems_task_delete(rval);
		goto cleanup;
	}

cleanup:
	if ( RTEMS_SUCCESSFUL != sc ) {
		rval = 0;
	}
	return rval;
}

rtems_id blah_tid = 0;
void blah()
{
	while (1) {
		sleep(8);
		printf("Hippel\n");
		printf("Pippel\n");
		printf("Kippel\n");
		printf("Nippel\n");
		BREAKPOINT();
	}
	rtems_task_delete(RTEMS_SELF);
}

int
rtems_debug_start(int pri)
{

	rtems_gdb_tid = thread_helper("GDBd", 20, 20000+RTEMS_MINIMUM_STACK_SIZE, rtems_gdb_daemon, 0);
#if 1
	blah_tid = thread_helper("blah", 200, RTEMS_MINIMUM_STACK_SIZE, blah, 0);
#endif

	return !rtems_gdb_tid;
}

int
_cexpModuleFinalize(void *h)
{
RtemsDebugMsg n;
	if ( rtems_gdb_tid ) {
		fprintf(stderr,"GDB daemon still running; refuse to unload\n");
		return -1;
	}
	while ( (n = msgHeadDeQ(&freeList)) )
		free(n);
	return 0;
}


struct sockaddr_in blahaddr = {0};

void
_cexpModuleInitialize(void *h)
{
    blahaddr.sin_family = AF_INET;
    blahaddr.sin_port   = htons(RTEMS_GDB_PORT);

	crc32_init(crc32_table);
 	rtems_debug_start(40);
}

void
rtems_debug_stop()
{
int  sd;

	if ( blah_tid )
		rtems_task_delete(blah_tid);
	
	/* enqueue a special message */
	initialized = 0;
	rtems_semaphore_flush( gdb_pending_id );

	sd = rtems_gdb_sd;
	rtems_gdb_sd = -1;
	if ( sd >= 0 )
		close(sd);
}

/* restart the thread provided that it exists and
 * isn't suspended due to a 'real' exception (as opposed to
 * a breakpoint).
 */
static int
task_resume(RtemsDebugMsg msg, int sig)
{
rtems_status_code sc = -1;
	if ( rtems_remote_debug & DEBUG_SCHED )
		fprintf(stderr,"task_resume(%08x, %2i)\n",msg->tid, sig);
	if ( msg->tid ) {

		/* never really resume the dummy tid */
		if ( msg->tid == dummy_tid ) {
		    if ( dummy_frame_pc == rtems_gdb_tgt_get_pc( msg ) ) {
				theDummy = msg;
				return 0;
			} else {
				theDummy = 0;
				if ( rtems_remote_debug & DEBUG_SCHED )
					fprintf(stderr,"STARTING DUMMY with sig %i\n",msg->sig);
				msg->sig = SIGTRAP;
			}
		}
		/* if we attached to an already sleeping thread, don't resume
		 * don't resume DEAD threads that were suspended due to memory
		 * faults etc. either
		 */
		if ( SIGINT == msg->sig || (msg->frm && SIGTRAP == msg->sig) ) {
			msg->contSig = sig;
			assert(msg->node.p == msg->node.n && msg->node.p == &msg->node);
			/* ask the target specific code to help if they want to single
			 * step a frame-less task
			 */
			if ( msg->frm
			    || SIGCONT == sig
      /* HMMM - We can't just change the state in the TCB.
	   *        What if we the thread is soundly asleep? We
	   *        currently have no provision to undo the changes
	   *        made by tgt_single_step()...
				|| 0 == rtems_gdb_tgt_single_step(msg)
	   */
			   ) {
				if ( rtems_remote_debug & DEBUG_SCHED )
					fprintf(stderr,"Resuming 0x%08x with sig %i\n",msg->tid, msg->contSig);
				sc = rtems_task_resume(msg->tid);
			}
			return RTEMS_SUCCESSFUL == sc ? 0 : -2;
		} else {
			/* add to cemetery if not there already */
			if ( &msg->node == msg->node.p )
				cdll_splerge_tail(&cemetery, &msg->node);

			assert( threadOnListBwd(&cemetery, msg->tid) );

			msg->contSig = 0;
		}
	}
	return -1;
}


static RtemsDebugMsg
task_switch_to(RtemsDebugMsg cur, rtems_id new_tid)
{
	if ( rtems_remote_debug & DEBUG_SCHED )
		printf("SWITCH 0x%08x -> 0x%08x\n", cur ? cur->tid : 0, new_tid);

	if ( cur && cur->tid == new_tid )
		return cur;

	if ( new_tid == dummy_tid && theDummy ) {
		cur = theDummy;
		if ( ! threadOnListBwd(&stopped, new_tid) ) {
			if ( rtems_remote_debug & DEBUG_SLIST ) {
				fprintf(stderr,"stopped list: adding %x to head\n", cur->tid);
				assert(cur->node.p == cur->node.n && cur->node.n == &cur->node);
			}

			cdll_splerge_head(&stopped, (CdllNode)cur);
		}
		return cur;
	}

	if ( new_tid ) {
		rtems_status_code sc;
		switch ( (sc = rtems_task_suspend( new_tid )) ) {
			case RTEMS_ALREADY_SUSPENDED:
				/* Hmm - could be that this is a task that is in
				 * the list somewhere.
				 * NOTE: it is NOT necessary to lock the list while
				 *       we scan it since new elements could ONLY be
				 *		 added _after_ the current tail AND the target
				 *       we're looking for is already suspended and
				 *       hence somewhere between the anchor and the
				 *       current tail;
				 */
				{
				RtemsDebugMsg t;
					if ( (t = threadOnListBwd(&anchor, new_tid)) ) {
						unsigned long flags;
						/* found; dequeue and return */
						rtems_interrupt_disable(flags);
						cdll_remove_el(&t->node);
						rtems_interrupt_enable(flags);
						assert( RTEMS_SUCCESSFUL == rtems_semaphore_obtain( gdb_pending_id, RTEMS_NO_WAIT, RTEMS_NO_TIMEOUT ) );
						SEMA_DEC();
						cur = t;
						break;
					} else if ( ( t = threadOnListBwd(&cemetery, new_tid) ) ) {
						cur = t;
						break;
					} else if ( ( t = threadOnListBwd(&stopped, new_tid) ) ) {
						cur = t;
						break;
					} else {
						/* hit an already suspended thread
						 * FALL THROUGH and get a new (frameless) node
						 */
					}
				}
				/* FALL THRU */

			case RTEMS_SUCCESSFUL:
				/* We just stopped this thread */
				cur = msgAlloc();
				cur->sig = SIGINT;
				cur->tid = new_tid;
				break;

				
			default:
				cur->tid = 0;
				rtems_error(sc, "suspending target thread 0x%08x failed", new_tid);
				/* thread might have gone away; attach to helper */
				cur = theDummy; theDummy = 0;
			break;
		}
	}
	if ( cur->tid == dummy_tid ) {
		assert( !theDummy );
		theDummy = cur;
	}
	/* bring to head of stopped list */
	if ( threadOnListBwd(&stopped, cur->tid) ) {
		/* remove */
		if ( rtems_remote_debug & DEBUG_SLIST )
			fprintf(stderr,"stopped list: removing %x\n", cur->tid);
		cdll_remove_el(&cur->node);
	}
	/* add to head */
	if ( rtems_remote_debug & DEBUG_SLIST )
		fprintf(stderr,"stopped list: adding %x at head\n", cur->tid);
	cdll_splerge_head(&stopped, (CdllNode)cur);
return cur;
}

/* this is called from exception handler (ISR) context !! */
void rtems_debug_notify_and_suspend(RtemsDebugMsg msg)
{
	cdll_init_el(&msg->node);

#ifndef ONETHREAD_TEST
printk("NOTIFY with sig %i\n",msg->sig);
	if ( SIGCHLD == msg->sig ) {
		if ( rtems_gdb_break_tid && rtems_gdb_break_tid != msg->tid ) {
		/* breakpoint hit; only stop if thread matches */
			msg->contSig = SIGCONT;
			return;
		} else {
			msg->sig = SIGTRAP;
		}
	}
	/* hook into the list */
	cdll_splerge_tail(&anchor, &msg->node);

	/* notify the daemon that a stopped thread is available */
	rtems_semaphore_release(gdb_pending_id);
	SEMA_INC();
#else
	switch ( msg->sig ) {
		case SIGCHLD:
			/* breakpoint hit; only stop if thread matches */
			if ( !rtems_gdb_break_tid )
				rtems_gdb_break_tid = msg->tid;
			else if ( rtems_gdb_break_tid != msg->tid ) {
				msg->contSig = SIGCONT;
				return;
			}
			msg->sig = SIGTRAP;
			
			/* fall thru */
		case SIGTRAP: /* single step tracing */
			/* hook into the list */
			cdll_splerge_tail(&anchor, &msg->node);

			/* notify the daemon that a stopped thread is available */
			rtems_semaphore_release(gdb_pending_id);
			SEMA_INC();

			break;

		default:
			/* save dead thread in the cemetery */
			cdll_splerge_tail(&cemetery, &msg->node);
		break;
	}
#endif

	/* hackish but it should work:
	 * rtems_task_suspend should work for other APIs also...
	 * probably should check for 'local' node.
	 */
	rtems_task_suspend( msg->tid );
}

static RtemsDebugMsg getFirstMsg(int block)
{
RtemsDebugMsg		msg;
unsigned long		flags;
rtems_status_code	sc;

	if ( block ) {
		sc = rtems_semaphore_obtain(gdb_pending_id, RTEMS_WAIT, RTEMS_NO_TIMEOUT);
		if ( RTEMS_UNSATISFIED == sc ) {
			/* someone interrupted us by flushing the semaphore */
			return 0;
		} else {
			assert( RTEMS_SUCCESSFUL == sc );
			SEMA_DEC();
		}
	}

	rtems_interrupt_disable(flags);
	msg = msgHeadDeQ(&anchor);
	rtems_interrupt_enable(flags);

	if ( !msg )
		return 0;

	if ( !block ) {
		assert( RTEMS_SUCCESSFUL == rtems_semaphore_obtain( gdb_pending_id, RTEMS_NO_WAIT, RTEMS_NO_TIMEOUT) );
		SEMA_DEC();
	}
	if ( msg->tid == dummy_tid ) {
		assert( !theDummy );
		theDummy = msg;
	}
	assert( ! threadOnListBwd(&stopped, msg->tid) );

	if ( rtems_remote_debug & DEBUG_SLIST )
		fprintf(stderr,"stopped list: adding %x\n", msg->tid);

	assert( msg->node.p == &msg->node && msg->node.n == &msg->node );
	cdll_splerge_head(&stopped, &msg->node);
	return msg;
}

/* obtain the TCB of a thread.
 * NOTE that thread dispatching is enabled
 *      if this operation is successful
 *      (and disabled if unsuccessful)
 */

Thread_Control *
rtems_gdb_get_tcb_dispatch_off(rtems_id tid)
{
Objects_Locations	loc;
Thread_Control		*tcb = 0;

	if ( !tid )
		return 0;

	tcb = _Thread_Get(tid, &loc);

    if (OBJECTS_LOCAL!=loc || !tcb) {
		if (tcb)
			_Thread_Enable_dispatch();
        printk("Id %x not found on local node\n",tid);
    }
	return tcb;
}

static int
pendSomethingHappening(RtemsDebugMsg *pcurrent, int tid, char *buf)
{
RtemsDebugMsg msg;

  do {
	/* check if there's another message pending
	 * wait only if we succeeded in resuming the
	 * current thread!
     */

	/* tiny chances for a race condition here -- if they hit the
	 * button before we set the flag
	 */

	waiting = 1;
	msg = getFirstMsg( 0 == *pcurrent );
	waiting = 0;

	if ( !initialized ) {
		printf("Daemon killed;\n");
		return -1;
	}

	if ( msg ) {
		*pcurrent = msg;
	} else {
		/* no new message; two possibilities:
		 * a) current == 0 which means that we
		 *    successfully resumed and hence waited
		 *    -> wait interrupted.
		 * b) current != 0 -> no wait and no other
		 *    thread pending in queue
		 */

		if ( ! *pcurrent ) {
			printf("net event\n");
			/* should be '\003' */
			getDebugChar();
			/* stop the current thread */
			if ( !tid ) {
				/* nothing attached yet */
				strcpy(buf,"X03");
				return 1;
			}
  			*pcurrent = task_switch_to(*pcurrent, tid);
			(*pcurrent)->sig = SIGINT;
		}
		/* else
		 * couldn't restart the thread. It's dead
		 * or was already suspended; since there were
		 * no messages pending, we return the old signal status
		 */
	}
		/* another thread got a signal */
  } while ( !*pcurrent );
  if ( rtems_remote_debug & DEBUG_SCHED && !threadOnListBwd(&stopped, (*pcurrent)->tid ) ) {
	fprintf(stderr,"OOPS: msg %p, tid %x stoppedp %p\n",msg,(*pcurrent)->tid, stopped.p);
  }
  assert( threadOnListBwd(&stopped, (*pcurrent)->tid) );
  sprintf(buf,"T%02xthread:%08x;",(*pcurrent)->sig, (*pcurrent)->tid);
return 0;
}


