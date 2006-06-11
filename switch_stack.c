/* $Id$ */

/* architecture dependent implementation needs to define:
 *
 * SP_GET(sp)  read current stack pointer into 'sp' (for debugging)
 * BP_GET(bp)  read  frame base pointer into 'bp'
 * FLIP_REGS(diff) switch 'sp', 'bp' and whatever else is
 *             needed by 'diff'. Make sure stack is not used
 *             during the flip!
 * STACK_ALIGNMENT alignment requirement for stack
 * FRAME_SZ    how much space to set aside (in 32-bit WORDS)
 * PC(f)       value of instruction pointer in exception frame f
 * SP(f)       value of stack pointer in exception frame f
 */

/* max number of simultaneously stopped threads */
#define NUM_FRAMES	40

/*
 *
 * Here's what 'switched_stack_suspend' does:
 * 
 * PIOR TO entering GDB (via the context switch introduced by
 * 'rtems_task_suspend()'):
 *
 *  1) everything that was dumped on the stack as a result of the
 *     exception is copied to a private memory area (exception frame
 *     and the exception handler call stack, local vars etc).
 *  2) stack frame link chain is relocated and fixed.
 *     'msg' and 'msg->frm' pointers to the current RtemsDebugMsg are
       relocated.
 *  3) stack pointer and frame pointer registers are switched to the
 *     new, private stack.
 *     The SP and stack as seen by GDB is as if no exception handler
 *     existed.
 *
 *  CAVEAT: exception handler and routines called from it MUST NOT
 *          USE addresses to variables on the stack with the exception
 *          of the RtemsDebugMsg pointer passed to the 'notify' routine.
 *          This pointer is relocated by switched_stack_suspend().
 *
 * AFTER leaving GDB:
 *  1) private stack is copied back to the task stack area UNDERNEATH
 *     the saved SP (msg->frm->esp0), i.e., GDB is allowed to push stuff
 *     on the stack (it does so to call code on the target).
 *  2) stack frame link chain, 'msg' and 'msg->frm' pointers are relocated
 *  3) stack and frame pointer registers are switched back to the task
 *     stack.
 *  4) When the exception handler returns, it pops the exception frame
 *     and returns to EIP as found in the exception frame...
 *
 * Here's a schematic:
 *
 *  a)  prior to exception   frame ptr  FP -> prev_frame original frame
 *                                            ..........
 *                           stack ptr  SP -> .......... original bottom
 *  b)  exception happens,
 *      prologue executes
 *      and handler is entered:        -----> prev_frame original frame
 *                                     |      ..........
 *                                     |  --> .......... original bottom
 *                                     |  |   .......... \
 *                                     |  |   saved pc   |
 *                                     |  |   saved regs | exception frame
 *                                     |  --- saved sp   |
 *                            FP ----> ------ saved fp   /
 *                                            ..........
 *                            SP ---------->  .......... 
 *                                            
 *
 *  c)  stack is copied to private area:
 * 
 *      private stack:                  task stack:
 *
 *      ------------------------------------> prev_frame original frame
 *      |                                     ..........
 *      |  ---------------------------------> .......... original bottom
 *      |  |   .......... \
 *      |  |   pc         |
 *      |  |   regs       | exception frame
 *      |  --- sp         |
 * FP-> ------ fp         /
 *             ..........
 * SP----->    .......... 
 *                                            
 *
 *  d) GDB modifies task stack (pushes frames)
 * 
 *      private stack:                      task stack:
 *
 *      ---------------------------------   -> prev_frame original frame
 *      |                                |  |  ..........
 *      |  ---------------------------   |  |  .......... original bottom
 *      |  |   ..........  \           | |  |  xxxxxxxxxx \
 *      |  |   pc (GDB mod)|           | |  |  ...yyy.... |
 *      |  |   regs (GDB)  | exception | -> -- ..fp...... | GDB pushed frame
 *      |  --- sp (GDB mod)| frame     |       .......... |
 * FP-> ------ fp (GDB mod)/           |------>.......... /
 *             ..........
 * SP------>   .......... 
 *                                            
 *
 * e) AFTER return from 'notify' -- stack switched back:
 *
 *                                          task stack:
 *
 *                                          -> prev_frame original frame
 *                                          |  ..........
 *                                          |  .......... original bottom
 *                                          |  xxxxxxxxxx \
 *                                          |  ...yyy.... |
 *                                     -->  -- ..fp...... | GDB pushed frame
 *                                     |       .......... |
 *                                     |  ---->.......... /
 *                                     |  |   
 *                                     |  |   ..........  \ 
 *                                     |  |   pc (GDB mod)|
 *                                     |  |   regs (GDB)  | exception
 *                                     |  --- sp (GDB mod)| frame 
 *                                FP-> ------ fp (GDB mod)/
 *                                            ..........
 *                                SP------>   .......... 
 *
 * f) after return from exception
 *                                          task stack:
 *
 *                                          -> prev_frame original frame
 *                                          |  ..........
 *                                          |  .......... original bottom
 *                                          |  xxxxxxxxxx \
 *                                          |  ...yyy.... |
 *                             FP ------->  -- ..fp...... | GDB pushed frame
 *                                             .saved pc. |
 *                             SP ------------>.......... /
 */


#define RELOC(ptr) ((void*)((diff)+(unsigned long)(ptr)))

typedef union GdbStackFrameU_ *GdbStackFrame;

typedef union GdbStackFrameU_ {
	struct {
		unsigned long frame[FRAME_SZ];
		unsigned long lrroom[4];
	} stack;
	GdbStackFrame next;
} GdbStackFrameU
__attribute__((aligned(STACK_ALIGNMENT)));

static GdbStackFrameU savedStack[NUM_FRAMES] = {{{{0}}}};
static GdbStackFrame  freeStck = 0;

static void 
flip_stack(Frame top, long diff) __attribute__((noinline));

static void 
flip_stack(Frame top, long diff)
{
Frame         fix, tmp;
unsigned long bot;

	BP_GET(bot);

	/* fixup the frame pointers */

	/* the second test was necessary on m68k where GDB pushes
         * a frame that is not linked to the thread's frame stack
	 * but contains the address of a trap (for returning control
	 * to GDB).
	 * We must not relocate that last element in the chain.
         * ATM, I don't know a better way than checking if the
	 * address lies between bot..top. This hack only works
	 * for this special case, however... 
	 */
	for ( fix=(Frame)bot; fix->up < top && fix->up >= (Frame)bot; ) {
		tmp = fix->up;
		fix->up = RELOC(tmp);
		fix = tmp;
	}
	bot -= 100; /* what this routine needs */
	memcpy(RELOC(bot), (void*)bot, (unsigned)top - bot);

	/* switch to new stack */
	FLIP_REGS(diff);

if ( DEBUG_STACK & rtems_remote_debug ) {
	/* DEBUG: purge the old region; make sure it works */
	memset((void*)bot,0,(unsigned)top - bot);
}

}

static void
switched_stack_suspend(RtemsDebugMsg volatile m)
{
GdbStackFrame volatile stk;
unsigned long volatile diff;

	/* Here comes creepy stuff:
	 * GDB expects us to leave the stack as 
	 * the interrupted function left it.
	 * However, the whole exception handler has
	 * been using the thread stack which conflicts
	 * with this GDB requirement. Hence, we
	 * save everything into a separate area and
	 * switch the stack pointer.
	 */

	/* allocate a frame */
	if ( !(stk=freeStck) )
		rtems_fatal_error_occurred(RTEMS_NO_MEMORY);

	freeStck  = freeStck->next;
	stk->next = 0;

	/* fixup the exception frame pointer */
	/* copy frame; hopefully nobody upstream in the call stack
	 * uses other pointers into the frame...
	 */

	diff      =  (unsigned long)(stk->stack.frame+FRAME_SZ);
	diff     -=  (unsigned long)SP(m->frm);

#ifdef DEBUGGING_ENABLED
if ( DEBUG_STACK & rtems_remote_debug ) {
	unsigned sp,bp;
	printk("OLD STK %x,  m %x, m->frm %x\n",stk,m,m?(unsigned)m->frm:0xdeadbeef);
	SP_GET(sp); BP_GET(bp);
	printk("OLD BP  %x, SP %x, diff %x\n",bp,sp,diff);
}
#endif

	flip_stack((Frame)SP(m->frm), diff);

#ifdef DEBUGGING_ENABLED
if ( DEBUG_STACK & rtems_remote_debug ) {
	unsigned sp,bp;
	printk("NEW STK %x\n",stk);
	printk("PRE-RELOC: m %x, m->frm %x\n",m,m?(unsigned)m->frm:0xdeadbeef);
	SP_GET(sp); BP_GET(bp);
	printk("NEW BP  %x, SP %x diff %x\n",bp,sp,diff);
}
#endif

	m = RELOC(m);
	m->frm = RELOC(m->frm);

KDBGMSG(DEBUG_STACK, "POST-RELOC: m %x, m->frm %x\n",m,m?(unsigned)m->frm:0xdeadbeef);

	post_and_suspend(m);

	/* calculate diff again - stack pointer might have magically changed!!
	 * because gdb can push stuff on the stack (which is the main
	 * reason why we do the stack switching in the first place)
	 */
	diff      =  (unsigned long)SP(m->frm);
	diff     -=  (unsigned long)(stk->stack.frame+FRAME_SZ);

	/* switch back */
	flip_stack((Frame)stk->stack.lrroom,diff);

	m = RELOC(m); m->frm = RELOC(m->frm);

KDBGMSG(DEBUG_STACK, "BACK resuming at (m %x, frm %x) PC %x SP %x\n",
			m, m->frm, PC(m->frm), SP(m->frm));

	/* free up the frame -- this context runs until the
	 * frame is popped without interruption, hence adding
	 * it to the free list should be safe.
	 */

	stk->next = freeStck;
	freeStck  = stk;
}

static void
init_stack()
{
	for ( freeStck = savedStack + (NUM_FRAMES-1); freeStck > savedStack; freeStck-- )
		(freeStck-1)->next = freeStck;
}
