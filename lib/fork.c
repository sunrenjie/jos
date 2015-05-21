// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if (!(err & FEC_WR))
		panic("pgfault: faulting access to %08x not a write.\n", addr);
	if ((vpd[VPD(addr)] & (PTE_P|PTE_W|PTE_U)) != (PTE_P|PTE_W|PTE_U))
		panic("pgfault: faulting addr %08x inaccessible per pgdir.\n",
		      addr);
	if ((vpt[VPN(addr)] & (PTE_P|PTE_COW)) != (PTE_P|PTE_COW) ||
	    (vpt[VPN(addr)] & PTE_W) == PTE_W) // not COW page?
		panic("pgfault: page on faulting addr %08x not COW.\n", addr);

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.
	
	// LAB 4: Your code here.
	
	// TODO: no need to labour if the page is actually not shared.
	if ((r = sys_page_alloc(0, (void *)PFTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		panic("pgfault: sys_page_alloc: %e\n", r);
	memmove((void *)PFTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);
	if ((r = sys_page_map(0, (void *)PFTEMP, 0, ROUNDDOWN(addr, PGSIZE),
		PTE_P|PTE_U|PTE_W)) < 0)
		panic("pgfault: sys_page_map: %e\n", r);
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why mark ours copy-on-write again
// if it was already copy-on-write?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
// 
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
	void *addr;
	pte_t pte;
	int perm;

	// LAB 4: Your code here.
	addr = (void *)((uint32_t)pn * PGSIZE);
	pte = vpt[VPN(addr)];
	if (pte & PTE_SHARE) // copy mapping for shared page
		return sys_page_map(0, addr, envid, addr, (pte & PTE_USER));
	if ((pte & PTE_W) || (pte & PTE_COW))
		perm = PTE_P|PTE_U|PTE_COW;
	else
		perm = PTE_P|PTE_U;
	if ((r = sys_page_map(0, addr, envid, addr, perm)) < 0)
		return r;
	if (perm & PTE_COW)
		if ((r = sys_page_map(0, addr, 0, addr, perm)) < 0)
			return r;
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "env" and the user exception stack in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	int r;
	envid_t envid;
	void *va1, *va2;
	extern void _pgfault_upcall(void);

	set_pgfault_handler(pgfault);

	if ((envid = sys_exofork()) < 0)
		panic("fork: sys_exofork() failed: %e", envid);
	if (envid == 0) { // child
		env = envs + ENVX(sys_getenvid());
		return 0;
	}

	// parent prepare address space for the child
	for (va1 = (void *)USTABDATA; va1 < (void *)USTACKTOP; va1 += PTSIZE) {
		if (!(vpd[VPD(va1)] & PTE_P)) // page dir NA
			continue;
		for (va2 = ROUNDDOWN(va1, PTSIZE);
		     va2 < MIN(ROUNDDOWN(va1, PTSIZE) + PTSIZE, (void *)USTACKTOP);
		     va2 += PGSIZE) {
			if (!(vpt[VPN(va2)] & PTE_P) ||
			    !(vpt[VPN(va2)] & PTE_U)) // page table NA
				continue;
			if ((r = duppage(envid, VPN(va2))) < 0)
				panic("fork: duppage() failed: %e\n", r);
		}
	}

	if ((r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE),
	                   PTE_P|PTE_U|PTE_W)) < 0)
		panic("fork: sys_alloc() failed: %e\n", r);
	if ((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall) < 0))
		panic("fork: sys_env_set_pgfault_upcall failed: %e\n", r);
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("fork: sys_env_set_status() failed: %e\n", r);
	return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
