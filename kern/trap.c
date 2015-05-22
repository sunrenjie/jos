#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>

static struct Taskstate ts;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Falt",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
idt_init(void)
{
	extern struct Segdesc gdt[];
	
	// LAB 3: Your code here.
	extern void th_divide(void);
	extern void th_debug(void);
	extern void th_nmi(void);
	extern void th_brkpt(void);
	extern void th_oflow(void);
	extern void th_bound(void);
	extern void th_illop(void);
	extern void th_device(void);
	extern void th_dblflt(void);
	extern void th_tss(void);
	extern void th_segnp(void);
	extern void th_stack(void);
	extern void th_gpflt(void);
	extern void th_pgflt(void);
	extern void th_fperr(void);
	extern void th_align(void);
	extern void th_mchk(void);
	extern void th_simderr(void);
	extern void th_syscall(void);
	extern void th_default(void);
	extern void th_irq_0(void);
	extern void th_irq_1(void);
	extern void th_irq_2(void);
	extern void th_irq_3(void);
	extern void th_irq_4(void);
	extern void th_irq_5(void);
	extern void th_irq_6(void);
	extern void th_irq_7(void);
	extern void th_irq_8(void);
	extern void th_irq_9(void);
	extern void th_irq_10(void);
	extern void th_irq_11(void);
	extern void th_irq_12(void);
	extern void th_irq_13(void);
	extern void th_irq_14(void);
	extern void th_irq_15(void);

	SETGATE(idt[T_DIVIDE], 1, GD_KT, th_divide, 3)
	SETGATE(idt[T_DEBUG], 1, GD_KT, th_debug, 3)
	SETGATE(idt[T_NMI], 0, GD_KT, th_nmi, 3)
	SETGATE(idt[T_BRKPT], 0, GD_KT, th_brkpt, 3)
	SETGATE(idt[T_OFLOW], 1, GD_KT, th_oflow, 3)
	SETGATE(idt[T_BOUND], 1, GD_KT, th_bound, 3)
	SETGATE(idt[T_ILLOP], 1, GD_KT, th_illop, 3)
	SETGATE(idt[T_DEVICE], 0, GD_KT, th_device, 3)
	SETGATE(idt[T_DBLFLT], 1, GD_KT, th_dblflt, 3)
	SETGATE(idt[T_TSS], 1, GD_KT, th_tss, 3)
	SETGATE(idt[T_SEGNP], 1, GD_KT, th_segnp, 3)
	SETGATE(idt[T_STACK], 1, GD_KT, th_stack, 3)
	SETGATE(idt[T_GPFLT], 1, GD_KT, th_gpflt, 0) // TODO: improve this
	SETGATE(idt[T_PGFLT], 1, GD_KT, th_pgflt, 3)
	SETGATE(idt[T_FPERR], 1, GD_KT, th_fperr, 3)
	SETGATE(idt[T_ALIGN], 1, GD_KT, th_align, 3)
	SETGATE(idt[T_MCHK], 1, GD_KT, th_mchk, 3)
	SETGATE(idt[T_SIMDERR], 1, GD_KT, th_simderr, 3)
	SETGATE(idt[T_SYSCALL], 1, GD_KT, th_syscall, 3)
	SETGATE(idt[T_DEFAULT], 1, GD_KT, th_default, 3)
	SETGATE(idt[IRQ_OFFSET + 0], 0, GD_KT, th_irq_0, 0)
	SETGATE(idt[IRQ_OFFSET + 1], 0, GD_KT, th_irq_1, 0)
	SETGATE(idt[IRQ_OFFSET + 2], 0, GD_KT, th_irq_2, 0)
	SETGATE(idt[IRQ_OFFSET + 3], 0, GD_KT, th_irq_3, 0)
	SETGATE(idt[IRQ_OFFSET + 4], 0, GD_KT, th_irq_4, 0)
	SETGATE(idt[IRQ_OFFSET + 5], 0, GD_KT, th_irq_5, 0)
	SETGATE(idt[IRQ_OFFSET + 6], 0, GD_KT, th_irq_6, 0)
	SETGATE(idt[IRQ_OFFSET + 7], 0, GD_KT, th_irq_7, 0)
	SETGATE(idt[IRQ_OFFSET + 8], 0, GD_KT, th_irq_8, 0)
	SETGATE(idt[IRQ_OFFSET + 9], 0, GD_KT, th_irq_9, 0)
	SETGATE(idt[IRQ_OFFSET + 10], 0, GD_KT, th_irq_10, 0)
	SETGATE(idt[IRQ_OFFSET + 11], 0, GD_KT, th_irq_11, 0)
	SETGATE(idt[IRQ_OFFSET + 12], 0, GD_KT, th_irq_12, 0)
	SETGATE(idt[IRQ_OFFSET + 13], 0, GD_KT, th_irq_13, 0)
	SETGATE(idt[IRQ_OFFSET + 14], 0, GD_KT, th_irq_14, 0)
	SETGATE(idt[IRQ_OFFSET + 15], 0, GD_KT, th_irq_15, 0)

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS field of the gdt.
	gdt[GD_TSS >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate), 0);
	gdt[GD_TSS >> 3].sd_s = 0;

	// Load the TSS
	ltr(GD_TSS);

	// Load the IDT
	asm volatile("lidt idt_pd");
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	cprintf("  err  0x%08x\n", tf->tf_err);
	cprintf("  eip  0x%08x", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	cprintf("  esp  0x%08x", tf->tf_esp);
	cprintf("  ss   0x----%04x\n", tf->tf_ss);
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	switch(tf->tf_trapno) {
	case T_BRKPT:
		monitor(tf);
		return;
	case T_SYSCALL:
		tf->tf_regs.reg_eax = syscall(
			tf->tf_regs.reg_eax, tf->tf_regs.reg_edx,
			tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx,
			tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
		return;
	case T_PGFLT:
		page_fault_handler(tf);
		return;
	case IRQ_OFFSET:
		sched_yield();
		return;
	case IRQ_OFFSET + 1:
		kbd_intr();
		return;
	}

	// Handle clock and serial interrupts.
	// LAB 4: Your code here.

	// Handle keyboard interrupts.
	// LAB 5: Your code here.

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

static void
recover_tf_if_interrupted(struct Trapframe *tf)
{
	// Upon entering kernel mode, the first things the trap handlers do
	// will be to disable interrupt by 'cli' instruction. But the TH code
	// can still be interrupted, before the 'cli' instruction is executed.
	// In such cases, on top of the (partial) frame of the original trap
	// being handled, another interrupt trap frame is constructed on the
	// kernel stack.
	//
	// original trap has                 original trap has
	// no error code                     error code
	// (frame addr diff by 3)            (frame addr diff by 4)
	//
	//                                   |    ...   |
	//                                   |----------|
	// |    ...   |  upper part: trap    |    eip   |
	// |----------|  frame resulted from |----------|
	// |    eip   |  interrupting of the |     | cs |
	// |----------|  trap handler        |----------|
	// |     | cs |                      |  eflags  |
	// |----------|                  --> |==========|
	// |  eflags  |                  |   |    err   |
	// |==========| <- frame border --   |----------|
	// |    eip   |                      |    eip   |
	// |----------|                      |----------|
	// |     | cs |  lower part: the     |     | cs |
	// |----------|  (partial) frame of  |----------|
	// |  eflags  |  the trap whose      |  eflags  |
	// |----------|  handler is          |----------|
	// |    esp   |  interrupted before  |    esp   |
	// |----------|  execution of 'cli'  |----------|
	// |     | ss |                      |     | ss |
	// ============ <-- stack bottom --> ============
	//
	// Info about the bottom frame shall be recovered and copied to the
	// upper interrupt trap frame. Copying shall be performed from upper to
	// bottom as the two frames overlap and the bottom one will be
	// overwritten partially.

	extern void th_divide(void);
	extern void th_debug(void);
	extern void th_nmi(void);
	extern void th_brkpt(void);
	extern void th_oflow(void);
	extern void th_bound(void);
	extern void th_illop(void);
	extern void th_device(void);
	extern void th_dblflt(void);
	extern void th_tss(void);
	extern void th_segnp(void);
	extern void th_stack(void);
	extern void th_gpflt(void);
	extern void th_pgflt(void);
	extern void th_fperr(void);
	extern void th_align(void);
	extern void th_mchk(void);
	extern void th_simderr(void);
	extern void th_syscall(void);
	extern void th_default(void);
	extern void th_irq_0(void);
	extern void th_irq_1(void);
	extern void th_irq_2(void);
	extern void th_irq_3(void);
	extern void th_irq_4(void);
	extern void th_irq_5(void);
	extern void th_irq_6(void);
	extern void th_irq_7(void);
	extern void th_irq_8(void);
	extern void th_irq_9(void);
	extern void th_irq_10(void);
	extern void th_irq_11(void);
	extern void th_irq_12(void);
	extern void th_irq_13(void);
	extern void th_irq_14(void);
	extern void th_irq_15(void);

	uint32_t tno;
	struct Trapframe *tf1 = ((struct Trapframe *) KSTACKTOP - 1);
	if (tf == tf1)  // same frame? then no TH interrupting; nothing to do
		return;
	// Shall already in kernel mode and actually handling interrupt
	assert((tf->tf_cs & 3) != 3 && tf->tf_trapno == IRQ_OFFSET);

	// Deduce the trap number of the trap whose TH is interrupted, based on
	// the fact that tf->tf_eip always contains address of the 'cli'
	// instruction, and hence the TH address, since 'cli' instructions are
	// always the first ones of the THs.
	if      (tf->tf_eip == (uintptr_t) &th_divide)  tno = T_DIVIDE;
	else if (tf->tf_eip == (uintptr_t) &th_debug)   tno = T_DEBUG;
	else if (tf->tf_eip == (uintptr_t) &th_nmi)     tno = T_NMI;
	else if (tf->tf_eip == (uintptr_t) &th_brkpt)   tno = T_BRKPT;
	else if (tf->tf_eip == (uintptr_t) &th_oflow)   tno = T_OFLOW;
	else if (tf->tf_eip == (uintptr_t) &th_bound)   tno = T_BOUND;
	else if (tf->tf_eip == (uintptr_t) &th_illop)   tno = T_ILLOP;
	else if (tf->tf_eip == (uintptr_t) &th_device)  tno = T_DEVICE;
	else if (tf->tf_eip == (uintptr_t) &th_dblflt)  tno = T_DBLFLT;
	else if (tf->tf_eip == (uintptr_t) &th_tss)     tno = T_TSS;
	else if (tf->tf_eip == (uintptr_t) &th_segnp)   tno = T_SEGNP;
	else if (tf->tf_eip == (uintptr_t) &th_stack)   tno = T_STACK;
	else if (tf->tf_eip == (uintptr_t) &th_gpflt)   tno = T_GPFLT;
	else if (tf->tf_eip == (uintptr_t) &th_pgflt)   tno = T_PGFLT;
	else if (tf->tf_eip == (uintptr_t) &th_fperr)   tno = T_FPERR;
	else if (tf->tf_eip == (uintptr_t) &th_align)   tno = T_ALIGN;
	else if (tf->tf_eip == (uintptr_t) &th_mchk)    tno = T_MCHK;
	else if (tf->tf_eip == (uintptr_t) &th_simderr) tno = T_SIMDERR;
	else if (tf->tf_eip == (uintptr_t) &th_syscall) tno = T_SYSCALL;
	else if (tf->tf_eip == (uintptr_t) &th_default) tno = T_DEFAULT;
	else if (tf->tf_eip == (uintptr_t) &th_irq_0)   tno = IRQ_OFFSET + 0;
	else if (tf->tf_eip == (uintptr_t) &th_irq_1)   tno = IRQ_OFFSET + 1;
	else if (tf->tf_eip == (uintptr_t) &th_irq_2)   tno = IRQ_OFFSET + 2;
	else if (tf->tf_eip == (uintptr_t) &th_irq_3)   tno = IRQ_OFFSET + 3;
	else if (tf->tf_eip == (uintptr_t) &th_irq_4)   tno = IRQ_OFFSET + 4;
	else if (tf->tf_eip == (uintptr_t) &th_irq_5)   tno = IRQ_OFFSET + 5;
	else if (tf->tf_eip == (uintptr_t) &th_irq_6)   tno = IRQ_OFFSET + 6;
	else if (tf->tf_eip == (uintptr_t) &th_irq_7)   tno = IRQ_OFFSET + 7;
	else if (tf->tf_eip == (uintptr_t) &th_irq_8)   tno = IRQ_OFFSET + 8;
	else if (tf->tf_eip == (uintptr_t) &th_irq_9)   tno = IRQ_OFFSET + 9;
	else if (tf->tf_eip == (uintptr_t) &th_irq_10)  tno = IRQ_OFFSET + 10;
	else if (tf->tf_eip == (uintptr_t) &th_irq_11)  tno = IRQ_OFFSET + 11;
	else if (tf->tf_eip == (uintptr_t) &th_irq_12)  tno = IRQ_OFFSET + 12;
	else if (tf->tf_eip == (uintptr_t) &th_irq_13)  tno = IRQ_OFFSET + 13;
	else if (tf->tf_eip == (uintptr_t) &th_irq_14)  tno = IRQ_OFFSET + 14;
	else if (tf->tf_eip == (uintptr_t) &th_irq_15)  tno = IRQ_OFFSET + 15;
	else panic("the interrupted TH at 0x%08x is not recognized.\n");
	tf->tf_trapno = tno;

	// Copy relevant values from the bottom trap frame in the upper frame.
	if (&tf1->tf_eip - &tf->tf_eip == 4)
		tf->tf_err = tf1->tf_err;
	else
		assert(&tf1->tf_eip - &tf->tf_eip == 3);
	tf->tf_eip = tf1->tf_eip;
	tf->tf_cs = tf1->tf_cs;
	tf->tf_eflags = tf1->tf_eflags;
	tf->tf_esp = tf1->tf_esp;
	tf->tf_ss = tf1->tf_ss;
}

void
trap(struct Trapframe *tf)
{
	recover_tf_if_interrupted(tf);
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		assert(curenv);
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}
	
	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNABLE)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;
	void *top;
	struct UTrapframe *utf;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.
	
	// LAB 3: Your code here.

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack, or the exception stack overflows,
	// then destroy the environment that caused the fault.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').
	
	// LAB 4: Your code here.
	if ((tf->tf_cs & 3) == 0) {
		print_trapframe(tf);
		panic("kerel page fault\n");
	}
	if (!curenv->env_pgfault_upcall) {
		cprintf("[%08x] user env_pgfault_upcall not set.\n");
		goto destroy;
	}
	user_mem_assert(curenv, curenv->env_pgfault_upcall, 1, PTE_P|PTE_U);
	user_mem_assert(curenv, (void *)UXSTACKTOP-PGSIZE, PGSIZE,
		PTE_P|PTE_U|PTE_W);
	if (tf->tf_esp >= UXSTACKTOP-PGSIZE && tf->tf_esp < UXSTACKTOP) {
		// fault-handling code fault; leave an extra dword 0
		top = (void *)(tf->tf_esp - sizeof(uint32_t));
		*((uint32_t *)top) = 0;
	} else
		top = (void *)UXSTACKTOP;
	utf = (struct UTrapframe *) (top - sizeof(struct UTrapframe));
	if ((void *)utf < (void *)(UXSTACKTOP - PGSIZE)) {
		cprintf("[%08x] user exception stack overflow.\n");
		goto destroy;
	}
	utf->utf_fault_va = fault_va;
	utf->utf_err = tf->tf_err;
	utf->utf_regs = tf->tf_regs;
	utf->utf_eip = tf->tf_eip;
	utf->utf_eflags = tf->tf_eflags;
	utf->utf_esp = tf->tf_esp;
	// Finally, execute current env @ page fault handler.
	curenv->env_tf.tf_eip = (uint32_t)curenv->env_pgfault_upcall;
	curenv->env_tf.tf_esp = (uint32_t)utf;
	env_run(curenv);
	return;

destroy:
	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

