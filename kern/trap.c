#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

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
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	cprintf("  err  0x%08x\n", tf->tf_err);
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	cprintf("  esp  0x%08x\n", tf->tf_esp);
	cprintf("  ss   0x----%04x\n", tf->tf_ss);
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	if (tf->tf_trapno == T_BRKPT)
		monitor(tf);
	else if (tf->tf_trapno == T_SYSCALL)
		tf->tf_regs.reg_eax = syscall(
			tf->tf_regs.reg_eax, tf->tf_regs.reg_edx,
			tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx,
			tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
	

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	cprintf("Incoming TRAP frame at %p\n", tf);

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

        // Return to the current environment, which should be runnable.
        assert(curenv && curenv->env_status == ENV_RUNNABLE);
        env_run(curenv);
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

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

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

