/****************************************************************************

		THIS SOFTWARE IS NOT COPYRIGHTED  
   
   HP offers the following for use in the public domain.  HP makes no
   warranty with regard to the software or it's performance and the 
   user accepts the software "AS IS" with all faults.

   HP DISCLAIMS ANY WARRANTIES, EXPRESS OR IMPLIED, WITH REGARD
   TO THIS SOFTWARE INCLUDING BUT NOT LIMITED TO THE WARRANTIES
   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

****************************************************************************/

/****************************************************************************
 *  Header: remcom.c,v 1.34 91/03/09 12:29:49 glenne Exp $                   
 *
 *  Module name: remcom.c $  
 *  Revision: 1.34 $
 *  Date: 91/03/09 12:29:49 $
 *  Contributor:     Lake Stevens Instrument Division$
 *  
 *  Description:     low level support for gdb debugger. $
 *
 *  Considerations:  only works on target hardware $
 *
 *  Written by:      Glenn Engel $
 *  ModuleState:     Experimental $ 
 *
 *  NOTES:           See Below $
 * 
 *  To enable debugger support, two things need to happen.  One, a
 *  call to set_debug_traps() is necessary in order to allow any breakpoints
 *  or error conditions to be properly intercepted and reported to gdb.
 *  Two, a breakpoint needs to be generated to begin communication.  This
 *  is most easily accomplished by a call to breakpoint().  Breakpoint()
 *  simulates a breakpoint by executing a trap #1.  The breakpoint instruction
 *  is hardwired to trap #1 because not to do so is a compatibility problem--
 *  there either should be a standard breakpoint instruction, or the protocol
 *  should be extended to provide some means to communicate which breakpoint
 *  instruction is in use (or have the stub insert the breakpoint).
 *  
 *  Some explanation is probably necessary to explain how exceptions are
 *  handled.  When an exception is encountered the 68000 pushes the current
 *  program counter and status register onto the supervisor stack and then
 *  transfers execution to a location specified in it's vector table.
 *  The handlers for the exception vectors are hardwired to jmp to an address
 *  given by the relation:  (exception - 256) * 6.  These are decending 
 *  addresses starting from -6, -12, -18, ...  By allowing 6 bytes for
 *  each entry, a jsr, jmp, bsr, ... can be used to enter the exception 
 *  handler.  Using a jsr to handle an exception has an added benefit of
 *  allowing a single handler to service several exceptions and use the
 *  return address as the key differentiation.  The vector number can be
 *  computed from the return address by [ exception = (addr + 1530) / 6 ].
 *  The sole purpose of the routine _catchException is to compute the
 *  exception number and push it on the stack in place of the return address.
 *  The external function exceptionHandler() is
 *  used to attach a specific handler to a specific m68k exception.
 *  For 68020 machines, the ability to have a return address around just
 *  so the vector can be determined is not necessary because the '020 pushes an
 *  extra word onto the stack containing the vector offset
 * 
 *  Because gdb will sometimes write to the stack area to execute function
 *  calls, this program cannot rely on using the supervisor stack so it
 *  uses it's own stack area reserved in the int array remcomStack.  
 * 
 *************
 *
 *    The following gdb commands are supported:
 * 
 * command          function                               Return value
 * 
 *    g             return the value of the CPU registers  hex data or ENN
 *    G             set the value of the CPU registers     OK or ENN
 * 
 *    mAA..AA,LLLL  Read LLLL bytes at address AA..AA      hex data or ENN
 *    MAA..AA,LLLL: Write LLLL bytes at address AA.AA      OK or ENN
 * 
 *    c             Resume at current address              SNN   ( signal NN)
 *    cAA..AA       Continue at address AA..AA             SNN
 * 
 *    s             Step one instruction                   SNN
 *    sAA..AA       Step one instruction from AA..AA       SNN
 * 
 *    k             kill
 *
 *    ?             What was the last sigval ?             SNN   (signal NN)
 * 
 * All commands and responses are sent with a packet which includes a 
 * checksum.  A packet consists of 
 * 
 * $<packet info>#<checksum>.
 * 
 * where
 * <packet info> :: <characters representing the command or response>
 * <checksum>    :: < two hex digits computed as modulo 256 sum of <packetinfo>>
 * 
 * When a packet is received, it is first acknowledged with either '+' or '-'.
 * '+' indicates a successful transfer.  '-' indicates a failed transfer.
 * 
 * Example:
 * 
 * Host:                  Reply:
 * $m0,10#2a               +$00010203040506070809101112131415#42
 * 
 ****************************************************************************/

#define __RTEMS_VIOLATE_KERNEL_VISIBILITY__
#include <rtems.h>
#include <rtems/error.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>

typedef struct RtemsDebugMsgRec_ *RtemsDebugMsg;

#ifdef __PPC__
#include "rtems-gdb-stub-ppc-shared.h"
#else
#error need target specific helper implementation
#endif

/* special messages */
#define GDB_NET  1
#define GDB_KILL 0

#define TID_ANY ((rtems_id)0)
#define TID_ALL ((rtems_id)-1)

typedef struct RtemsDebugMsgRec_ {
	rtems_id	    tid;
	RtemsDebugFrame frm;
	int             sig;
} RtemsDebugMsgRec;

/************************************************************************
 *
 * external low-level support routines 
 */

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


/************************/
/* FORWARD DECLARATIONS */
/************************/

/************************************************************************/
/* BUFMAX defines the maximum number of characters in inbound/outbound buffers*/
/* at least NUMREGBYTES*2 are needed for register packets */
#define BUFMAX 400
#define STATIC 

#define CTRLC  3
#define RTEMS_GDB_Q_LEN 200
#define RTEMS_GDB_PORT 4444

#if BUFMAX < 2*NUMREGBYTES
#  undef  BUFMAX
#  define BUFMAX 2*NUMREGBYTES+100
#endif

static char initialized;  /* boolean flag. != 0 means we've been initialized */

int     rtems_remote_debug = 4;
/*  debug >  0 prints ill-formed commands in valid packets & checksum errors */ 

static const char hexchars[]="0123456789abcdef";

/************* jump buffer used for setjmp/longjmp **************************/
STATIC jmp_buf remcomEnv;

STATIC int
hex (ch)
     char ch;
{
  if ((ch >= 'a') && (ch <= 'f'))
    return (ch - 'a' + 10);
  if ((ch >= '0') && (ch <= '9'))
    return (ch - '0');
  if ((ch >= 'A') && (ch <= 'F'))
    return (ch - 'A' + 10);
  return (-1);
}

STATIC char remcomInBuffer[BUFMAX];
STATIC char remcomOutBuffer[BUFMAX];

/* scan for the sequence $<data>#<checksum>     */
#define GETCHAR() \
	  do { if ( (ch = getDebugChar()) < 0 ) return 0; }  while (0)

STATIC unsigned char *
getpacket (void)
{
  unsigned char *buffer = &remcomInBuffer[0];
  unsigned char checksum;
  unsigned char xmitcsum;
  int count;
  int ch;

  while (1)
    {
      /* wait around for the start character, ignore all other characters */
	  do {
		GETCHAR();
      } while (ch != '$')
	;

    retry:
      checksum = 0;
      xmitcsum = -1;
      count = 0;

      /* now, read until a # or end of buffer is found */
      while (count < BUFMAX)
	{
	  GETCHAR();
	  if (ch == '$')
	    goto retry;
	  if (ch == '#')
	    break;
	  checksum = checksum + ch;
	  buffer[count] = ch;
	  count = count + 1;
	}
      buffer[count] = 0;

      if (ch == '#')
	{
	  GETCHAR();
	  xmitcsum = hex (ch) << 4;
	  GETCHAR();
	  xmitcsum += hex (ch);

	  if (checksum != xmitcsum)
	    {
	      if (rtems_remote_debug)
		{
		  fprintf (stderr,
			   "bad checksum.  My count = 0x%x, sent=0x%x. buf=%s\n",
			   checksum, xmitcsum, buffer);
		}
	      putDebugChar ('-');	/* failed checksum */
          flushDebugChars();
	    }
	  else
	    {
          unsigned char *rval;
	      putDebugChar ('+');	/* successful transfer */

	      /* if a sequence char is present, reply the sequence ID */
	      if (buffer[2] == ':')
		{
		  putDebugChar (buffer[0]);
		  putDebugChar (buffer[1]);

		  rval = &buffer[3];
		} else {
		  rval = &buffer[0];
		}
		flushDebugChars();
		return rval;
	    }
	}
    }
}

/* send the packet in buffer. */

STATIC void
putpacket (buffer)
     char *buffer;
{
  unsigned char checksum;
  int count;
  char ch;

  /*  $<packet info>#<checksum>. */
  do
    {
      putDebugChar ('$');
      checksum = 0;
      count = 0;
      while ( (ch = buffer[count]) )
	{
	  putDebugChar (ch);
	  checksum += ch;
	  count += 1;
	}

      putDebugChar ('#');
      putDebugChar (hexchars[checksum >> 4]);
      putDebugChar (hexchars[checksum % 16]);
      flushDebugChars();
	if ( rtems_remote_debug > 2 ) {
		fprintf(stderr,"Putting packet (len %i)\n",count);
	}


	  count = getDebugChar();
  } while ( count >= 0 && count != '+');

}

STATIC void
debug_error (char *format, char *parm)
{
  if (rtems_remote_debug)
    fprintf (stderr, format, parm);
}

/* convert the memory pointed to by mem into hex, placing result in buf */
/* return a pointer to the last char put in buf (null) */
STATIC char *
mem2hex (mem, buf, count)
     char *mem;
     char *buf;
     int count;
{
  int i;
  unsigned char ch;
  for (i = 0; i < count; i++)
    {
      ch = *mem++;
      *buf++ = hexchars[ch >> 4];
      *buf++ = hexchars[ch % 16];
    }
  *buf = 0;
  return (buf);
}

/* integer to BE hex; buffer must be large enough */

STATIC char *
intToHex(int i, char *buf)
{
register int j = 2*sizeof(i);
	buf[j--]=0;
	do {
		buf[j--] = hexchars[i&0xf];
		i>>=4;
	} while ( j>0 );
	return buf+2*sizeof(i);
}

/* convert the hex array pointed to by buf into binary to be placed in mem */
/* return a pointer to the character AFTER the last byte written */
STATIC char *
hex2mem (buf, mem, count)
     char *buf;
     char *mem;
     int count;
{
  int i;
  unsigned char ch;
  for (i = 0; i < count; i++)
    {
      ch = hex (*buf++) << 4;
      ch = ch + hex (*buf++);
      *mem++ = ch;
    }
  return (mem);
}

/* a bus error has occurred, perform a longjmp
   to return execution and allow handling of the error */

STATIC void
handle_buserror ()
{
  longjmp (remcomEnv, 1);
}

/* this function takes the 68000 exception number and attempts to 
   translate this number into a unix compatible signal value */
STATIC int
computeSignal (exceptionVector)
     int exceptionVector;
{
  int sigval;
  switch (exceptionVector)
    {
    case 2:
      sigval = 10;
      break;			/* bus error           */
    case 3:
      sigval = 10;
      break;			/* address error       */
    case 4:
      sigval = 4;
      break;			/* illegal instruction */
    case 5:
      sigval = 8;
      break;			/* zero divide         */
    case 6:
      sigval = 8;
      break;			/* chk instruction     */
    case 7:
      sigval = 8;
      break;			/* trapv instruction   */
    case 8:
      sigval = 11;
      break;			/* privilege violation */
    case 9:
      sigval = 5;
      break;			/* trace trap          */
    case 10:
      sigval = 4;
      break;			/* line 1010 emulator  */
    case 11:
      sigval = 4;
      break;			/* line 1111 emulator  */

      /* Coprocessor protocol violation.  Using a standard MMU or FPU
         this cannot be triggered by software.  Call it a SIGBUS.  */
    case 13:
      sigval = 10;
      break;

    case 31:
      sigval = 2;
      break;			/* interrupt           */
    case 33:
      sigval = 5;
      break;			/* breakpoint          */

      /* This is a trap #8 instruction.  Apparently it is someone's software
         convention for some sort of SIGFPE condition.  Whose?  How many
         people are being screwed by having this code the way it is?
         Is there a clean solution?  */
    case 40:
      sigval = 8;
      break;			/* floating point err  */

    case 48:
      sigval = 8;
      break;			/* floating point err  */
    case 49:
      sigval = 8;
      break;			/* floating point err  */
    case 50:
      sigval = 8;
      break;			/* zero divide         */
    case 51:
      sigval = 8;
      break;			/* underflow           */
    case 52:
      sigval = 8;
      break;			/* operand error       */
    case 53:
      sigval = 8;
      break;			/* overflow            */
    case 54:
      sigval = 8;
      break;			/* NAN                 */
    default:
      sigval = 7;		/* "software generated" */
    }
  return (sigval);
}

/**********************************************/
/* WHILE WE FIND NICE HEX CHARS, BUILD AN INT */
/* RETURN NUMBER OF CHARS PROCESSED           */
/**********************************************/
STATIC int
hexToInt (char **ptr, int *intValue)
{
  int numChars = 0;
  int hexValue;

  *intValue = 0;

  while (**ptr)
    {
      hexValue = hex (**ptr);
      if (hexValue >= 0)
	{
	  *intValue = (*intValue << 4) | hexValue;
	  numChars++;
	}
      else
	break;

      (*ptr)++;
    }

  return (numChars);
}

rtems_id       rtems_gdb_q    = 0;
int            rtems_gdb_sd   = -1;

static void sowake(struct socket *so, caddr_t arg)
{
char ch;
	printk("..SOWAKE..\n");
	ch = GDB_NET;
	rtems_message_queue_urgent(rtems_gdb_q, &ch, sizeof(ch));
}

static void cleanup_connection()
{
	/* remove all breakpoints and continue all threads */
	fclose( rtems_gdb_strm );
	rtems_gdb_strm = 0;
}

static int
havestate(RtemsDebugMsg m)
{
	if ( TID_ANY == m->tid || TID_ALL == m->tid || !m->frm ) {
		strcpy(remcomOutBuffer,"E12");
		return 0;
	}
	return 1;
}

static rtems_id *
get_tid_tab(rtems_id *t)
{
int                 max, cur, i, api;
Objects_Information *info;
Objects_Control		*c;
	/* count slots */
	{
again:
		/* get current estimate */
		for ( max=0, api=0; api<=OBJECTS_APIS_LAST; api++ )
			max += _Objects_Information_table[api][1/* thread class for all APIs*/]->maximum;
		t = realloc(t, sizeof(rtems_id)*(max+1));

		if ( t ) {
			cur = 0;
			_Thread_Disable_dispatch();
			for ( api=0; api<=OBJECTS_APIS_LAST; api++ ) {
				info = _Objects_Information_table[api][1/* thread class for all APIs*/];
				for ( i=0; i<info->maximum && (c=info->local_table[i]); i++ ) {
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

/*
 * This function does all command processing for interfacing to gdb.
 */
STATIC void
rtems_gdb_daemon ()
{
  int stepping;
  int addr, length;
  char              *ptr, *chpt;
  char              *regbuf = 0;
  int               sd;
  RtemsDebugMsgRec  msg = {0};
  int               msgsize;
  rtems_status_code sc;
  rtems_id          contTid  = 0;
  rtems_id          *tid_tab = calloc(1,sizeof(rtems_id));
  int               ehandler_installed=0;

  /* startup / initialization */
  {
	if ( !(regbuf = malloc(NUMREGBYTES)) ) {
		fprintf(stderr,"no memory\n");
		goto cleanup;
	}
	/* create message queue */
	if ( RTEMS_SUCCESSFUL !=
	     rtems_message_queue_create(
			rtems_build_name('G','D','B','Q'),
			RTEMS_GDB_Q_LEN,
			sizeof(RtemsDebugMsgRec),
			RTEMS_DEFAULT_ATTRIBUTES,
			&rtems_gdb_q) )
		goto cleanup;
    /* create socket */
    rtems_gdb_sd = socket(PF_INET, SOCK_STREAM, 0);
	if ( rtems_gdb_sd < 0 ) {
		perror("GDB daemon: socket");
		goto cleanup;
	}
	{
    int                arg = 1;
    struct sockaddr_in srv; 
    struct sockwakeup  wkup;

      setsockopt(rtems_gdb_sd, SOL_SOCKET, SO_KEEPALIVE, &arg, sizeof(arg));
      setsockopt(rtems_gdb_sd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg));
      wkup.sw_pfn = sowake;
      wkup.sw_arg = 0;
#if 0
      setsockopt(rtems_gdb_sd, SOL_SOCKET, SO_RCVWAKEUP, &wkup, sizeof(wkup));
#endif

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
  }

  while (1) {
	if ( rtems_gdb_strm )
		fclose(rtems_gdb_strm);
	{
	struct sockaddr_in a;
	size_t             a_s = sizeof(a);
	if ( (sd = accept(rtems_gdb_sd, (struct sockaddr *)&a, &a_s)) < 0 ) {
		perror("GDB daemon: accept");
		goto cleanup;
	}
	}
	if ( !(rtems_gdb_strm = fdopen(sd, "r+")) ) {
		perror("GDB daemon: unable to open stream");
		close(sd);
		goto cleanup;
	}

	while (1) {

	if ( RTEMS_SUCCESSFUL !=
         (sc = rtems_message_queue_receive(
            rtems_gdb_q, 
            &msg,
            &msgsize,
            RTEMS_WAIT,
            RTEMS_NO_TIMEOUT)) ) {
        rtems_error(sc,"GDB daemon: unable to rcv messages, exiting...");
        cleanup_connection();
		goto cleanup;
    }
	printk("got message size %i\n",msgsize);

	if ( msgsize < sizeof(RtemsDebugMsgRec) ) {
      char ch = *(char*)&msg;
      int  n;
      if ( GDB_KILL == ch ) {
			cleanup_connection();
			goto cleanup;
      }
	  /* activity on the socket while we are waiting for
       * something happening on the target
       */
      n = recv(sd, &ch, sizeof(ch), MSG_PEEK );
	  fprintf(stderr,"recvd n=%i\n", n);
	  if ( n <= 0 ) {
		perror("GDB daemon receive; connection dead?");
         /* connection probably dead */
			break;
	  }
      if ( CTRLC == ch ) {
		fprintf(stderr,"TODO -- CTRLC handling\n");
	  }
	  /* ignore */
	  continue;
	}

  if (rtems_remote_debug)
    printf ("signal=%d\n", msg.sig);

  /* reply to host that an exception has occurred */
  remcomOutBuffer[0] = 'S';
  remcomOutBuffer[1] = hexchars[msg.sig >> 4];
  remcomOutBuffer[2] = hexchars[msg.sig % 16];
  remcomOutBuffer[3] = 0;

  putpacket (remcomOutBuffer);

  stepping = 0;

  while (1 == 1)
    {
      remcomOutBuffer[0] = 0;
      ptr = getpacket ();
	  if (!ptr) {
		fprintf(stderr,"Link broken? -- disconnect\n");
		goto release_connection;
	  }
	if (rtems_remote_debug > 2) {
		printf("Got packet '%c' \n", *ptr);
	}
      switch (*ptr++)
	{
	default:
	  strcpy(remcomOutBuffer,"E10");
	  break;
	case '?':
	  remcomOutBuffer[0] = 'S';
	  remcomOutBuffer[1] = hexchars[msg.sig >> 4];
	  remcomOutBuffer[2] = hexchars[msg.sig % 16];
	  remcomOutBuffer[3] = 0;
	  break;
	case 'd':
	  rtems_remote_debug = !(rtems_remote_debug);	/* toggle debug flag */
	  break;
	case 'g':		/* return the value of the CPU registers */
	  if (!havestate(&msg))
		break;
	  mem2hex ((char *) regbuf, remcomOutBuffer, NUMREGBYTES);
	  break;
	case 'G':		/* set the value of the CPU registers - return OK */
	  if (!havestate(&msg))
		break;
	  hex2mem (ptr, (char *) regbuf, NUMREGBYTES);
	  rtems_gdb_tgt_r2f(msg.frm, msg.tid, regbuf);
	  strcpy (remcomOutBuffer, "OK");
	  break;

    case 'H':
      { rtems_id tid;
	  	sscanf(ptr+1,"%i",&tid);
	  if ( 'c' == *ptr ) {
		contTid = tid;
		if ( rtems_remote_debug ) {
			printf("New 'C' thread id set: 0x%08x\n",contTid);
		}
	  }
	  }
    break;

	  /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
	case 'm':
	  if (setjmp (remcomEnv) == 0)
	    {
	      /* TRY TO READ %x,%x.  IF SUCCEED, SET PTR = 0 */
	      if (hexToInt (&ptr, &addr))
		if (*(ptr++) == ',')
		  if (hexToInt (&ptr, &length))
		    {
		      ptr = 0;
		      mem2hex ((char *) addr, remcomOutBuffer, length);
		    }

	      if (ptr)
		{
		  strcpy (remcomOutBuffer, "E01");
		}
	    }
	  else
	    {
	      strcpy (remcomOutBuffer, "E03");
	      debug_error ("%s\n","bus error");
	    }

	  break;

	  /* MAA..AA,LLLL: Write LLLL bytes at address AA.AA return OK */
	case 'M':
	  if (setjmp (remcomEnv) == 0)
	    {
	      /* TRY TO WRITE '%x,%x:'.  IF SUCCEED, SET PTR = 0 */
	      if (hexToInt (&ptr, &addr))
		if (*(ptr++) == ',')
		  if (hexToInt (&ptr, &length))
		    if (*(ptr++) == ':')
		      {
			hex2mem (ptr, (char *) addr, length);
			ptr = 0;
			strcpy (remcomOutBuffer, "OK");
		      }
	      if (ptr)
		{
		  strcpy (remcomOutBuffer, "E02");
		}
	    }
	  else
	    {
	      strcpy (remcomOutBuffer, "E03");
	      debug_error ("%s\n","bus error");
	    }

	  break;

#if 0
	  /* cAA..AA    Continue at address AA..AA(optional) */
	  /* sAA..AA   Step one instruction from AA..AA(optional) */
	case 's':
	  stepping = 1;
	case 'c':
	  /* try to read optional parameter, pc unchanged if no parm */
	  if (hexToInt (&ptr, &addr))
	    registers[PC] = addr;

	  newPC = registers[PC];

	  /* clear the trace bit */
	  registers[PS] &= 0x7fff;

	  /* set the trace bit if we're stepping */
	  if (stepping)
	    registers[PS] |= 0x8000;

	  if (rtems_remote_debug)
	    printf ("new pc = 0x%x\n", newPC);

	  _returnFromException (msg.frm);	/* this is a jump */

#warning TODO /s/c/
#endif
	  break;

	  /* kill the program */
	case 'k':		/* do nothing */
	  break;

	case 'q':
      if ( !strcmp(ptr,"Offsets") ) {
		/* ignore; use values from file */
	  } else if ( !strcmp(ptr+1,"ThreadInfo") ) {
		int tidx = 0;
		if ( 'f' == *ptr ) {
			tidx = 0;
			/* TODO get thread snapshot */
			tid_tab = get_tid_tab(tid_tab);
		}
		chpt    = remcomOutBuffer;
		if ( !tid_tab[tidx] ) {
			strcpy(chpt,"l");
		} else {
			while ( tid_tab[tidx] && chpt < remcomOutBuffer + sizeof(remcomOutBuffer) - 20 ) {
				*chpt++ = ',';
				chpt    = intToHex(tid_tab[tidx++], chpt);
			}
			remcomOutBuffer[0]='m';
		}
	  }
	  break;
	}			/* switch */

      /* reply to the request */
      putpacket (remcomOutBuffer);
    }
  }
release_connection:
  cleanup_connection();

  }

/* shutdown */
cleanup:
  if ( ehandler_installed ) {
	rtems_debug_install_ehandler(0);
  }
  if ( rtems_gdb_q ) {
    rtems_message_queue_delete(rtems_gdb_q);
    rtems_gdb_q = 0;
  }
  if ( rtems_gdb_strm ) {
	fclose(rtems_gdb_strm);
	rtems_gdb_strm = 0;
  }
  if ( 0 <= rtems_gdb_sd ) {
    close(rtems_gdb_sd);
  }
  free( regbuf );
  free( tid_tab );

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

int
rtems_debug_start(int pri)
{
rtems_status_code sc;
rtems_id          tid = 0;

	if (0==pri)
		pri = 20;

	sc = rtems_task_create(	
			rtems_build_name('G','D','B','d'),
			pri,
			3*RTEMS_MINIMUM_STACK_SIZE,
			RTEMS_DEFAULT_MODES,
			RTEMS_LOCAL | RTEMS_FLOATING_POINT,
			&tid);
	if ( RTEMS_SUCCESSFUL != sc ) {
		rtems_error(sc, "Creating GDB daemon task");
		goto cleanup;
	}

	sc = rtems_task_start(tid, rtems_gdb_daemon, (rtems_task_argument)0);
	if ( RTEMS_SUCCESSFUL != sc ) {
		rtems_error(sc, "Starting GDB daemon");
		goto cleanup;
	}
	tid = 0;

cleanup:
	if ( tid )
		rtems_task_delete(tid);
	return sc;
}

int
_cexpModuleFinalize(void *h)
{
	if ( rtems_gdb_q ) {
		fprintf(stderr,"GDB daemon still running; refuse to unload\n");
		return -1;
	}
	return 0;
}


struct sockaddr_in blahaddr = {0};

void
_cexpModuleInitialize(void *h)
{
      blahaddr.sin_family = AF_INET;
      blahaddr.sin_port   = htons(RTEMS_GDB_PORT);
	  rtems_debug_start(40);
}

void
rtems_debug_stop()
{
char ch=GDB_KILL;
int  sd;
	rtems_message_queue_urgent(rtems_gdb_q, &ch, 1);
	sd = rtems_gdb_sd;
	rtems_gdb_sd = -1;
	if ( sd >= 0 )
		close(sd);
}

rtems_status_code
testDummySend()
{
extern void *dummyFrame;
RtemsDebugMsgRec msg;
	msg.tid = 0xdeadbeef;
	msg.frm = 0;
	msg.sig = 3;
	return rtems_message_queue_send(rtems_gdb_q,&msg,sizeof(msg));
}
