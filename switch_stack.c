/* $Id$ */

/* architecture dependent implementation needs to define:
 *
 * SP_GET(sp)  read current stack pointer into 'sp'
 * SP_PUT(val) load stack pointer register with 'val' 
 * BP_GET(bp)  read  frame base pointer into 'bp'
 * BP_PUT(val) write frame base pointer with 'val'
 * STACK_ALIGNMENT alignment requirement for stack
 * FRAME_SZ    how much space to set aside (in 32-bit WORDS)
 * PC(f)       value of instruction pointer in exception frame f
 * SP(f)       value of stack pointer in exception frame f
 */

/* max number of simultaneously stopped threads */
#define NUM_FRAMES	40

/*
 *
 * Here's what 'switch_stack' does:
 * 
 * PIOR TO entering GDB (via the 'notify_and_suspend()' routine):
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
 *          This pointer is relocated by switch_stack().
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
static GdbStackFrame freeList = 0;


static void 
flip_stack(Frame top, long diff)
{
Frame fix;
Frame sp,bp;

	SP_GET(sp);
	BP_GET(bp);

printk("OLD BOS %x -> %x\n",sp,  *(unsigned long*)sp);
printk("OLD TOS %x -> %x\n",top, *(unsigned long*)top);

	/* fixup the frame pointers */
	for ( fix=bp; fix < top; ) {
		fix->up = RELOC(fix->up);
		fix = fix->up;
	}
	memcpy(RELOC(sp), sp, (unsigned)top - (unsigned)sp);

	/* switch to new stack */
	SP_PUT(RELOC(sp));
	BP_PUT(RELOC(bp));
	

/* DEBUG: purge the old region; make sure it works */
memset((void*)sp,0,(unsigned)top - (unsigned)sp);

printk("NEW BOS %x -> %x\n",RELOC(sp),*(unsigned long*)RELOC(sp));
printk("NEW TOS %x -> %x\n",RELOC(top),*(unsigned long*)RELOC(top));
}

static void
switch_stack(RtemsDebugMsg m)
{
GdbStackFrame volatile stk;
unsigned long diff;

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
	if ( !(stk=freeList) )
		rtems_fatal_error_occurred(RTEMS_NO_MEMORY);

	freeList  = freeList->next;
	stk->next = 0;

	/* fixup the exception frame pointer */
	/* copy frame; hopefully nobody upstream in the call stack
	 * uses other pointers into the frame...
	 */

	diff      =  (unsigned long)(stk->stack.frame+FRAME_SZ);
	diff     -=  (unsigned long)SP(m->frm);

printk("OLD STK %x\n",stk);

	flip_stack((Frame)SP(m->frm), diff);

printk("NEW STK %x\n",stk);

	m = RELOC(m);
	m->frm = RELOC(m->frm);

	rtems_debug_notify_and_suspend(m);

	/* calculate diff again - stack pointer might have magically changed!!
	 * because gdb can push stuff on the stack (which is the main
	 * reason why we do the stack switching in the first place)
	 */
	diff      =  (unsigned long)SP(m->frm);
	diff     -=  (unsigned long)(stk->stack.frame+FRAME_SZ);

	/* switch back */
	flip_stack((Frame)stk->stack.lrroom,diff);

m = RELOC(m); m->frm = RELOC(m->frm);
printk("BACK resuming at PC %x SP %x\n",PC(m->frm), SP(m->frm));

	/* free up the frame -- this context runs until the
	 * frame is popped without interruption, hence adding
	 * it to the free list should be safe.
	 */

	stk->next = freeList;
	freeList  = stk;
}

static void
init_stack()
{
	for ( freeList = savedStack + (NUM_FRAMES-1); freeList > savedStack; freeList-- )
		(freeList-1)->next = freeList;
}
