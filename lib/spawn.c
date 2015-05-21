#include <inc/lib.h>
#include <inc/elf.h>

#define UTEMP2USTACK(addr)	((void*) (addr) + (USTACKTOP - PGSIZE) - UTEMP)
#define UTEMP2			(UTEMP + PGSIZE)
#define UTEMP3			(UTEMP2 + PGSIZE)

// [BINARY, BINARY + 0x8000000) will be used by spawn to load the program
// binary, while [SEGMENT, SEGMENT + 0x8000000) for preparing segments that
// need zeroing.
#define BINARY 0xB0000000
#define SEGMENT 0xB8000000

// Helper functions for spawn.
static int init_stack(envid_t child, const char **argv, uintptr_t *init_esp);
static int copy_shared_pages(envid_t child);

// Spawn a child process from a program image loaded from the file system.
// prog: the pathname of the program to run.
// argv: pointer to null-terminated array of pointers to strings,
// 	 which will be passed to the child as its command-line arguments.
// Returns child envid on success, < 0 on failure.
int
spawn(const char *prog, const char **argv)
{
	unsigned char elf_buf[512];
	struct Elf *elf;
	struct Proghdr *ph, *eph;
	struct Trapframe child_tf;
	envid_t child;
	int r, i, fdnum, file_size, delta, perm;
	void *binary, *segment, *segment_end, *va, *va2;

	// Insert your code, following approximately this procedure:
	//
	//   - Open the program file.
	//
	//   - Read the ELF header, as you have before, and sanity check its
	//     magic number.  (Check out your load_icode!)
	//
	//   - Use sys_exofork() to create a new environment.
	//
	//   - Set child_tf to an initial struct Trapframe for the child.
	//     Hint: The sys_exofork() system call has already created
	//     a good basis, in envs[ENVX(child)].env_tf.
	//     Hint: You must do something with the program's entry point.
	//     What?  (See load_icode!)
	//
	//   - Call the init_stack() function above to set up
	//     the initial stack page for the child environment.
	//
	//   - Map all of the program's segments that are of p_type
	//     ELF_PROG_LOAD into the new environment's address space.
	//     Use the p_flags field in the Proghdr for each segment
	//     to determine how to map the segment:
	//
	//	* If the ELF flags do not include ELF_PROG_FLAG_WRITE,
	//	  then the segment contains text and read-only data.
	//	  Use read_map() to read the contents of this segment,
	//	  and map the pages it returns directly into the child
	//        so that multiple instances of the same program
	//	  will share the same copy of the program text.
	//        Be sure to map the program text read-only in the child.
	//        Read_map is like read but returns a pointer to the data in
	//        *blk rather than copying the data into another buffer.
	//
	//	* If the ELF segment flags DO include ELF_PROG_FLAG_WRITE,
	//	  then the segment contains read/write data and bss.
	//	  As with load_icode() in Lab 3, such an ELF segment
	//	  occupies p_memsz bytes in memory, but only the FIRST
	//	  p_filesz bytes of the segment are actually loaded
	//	  from the executable file - you must clear the rest to zero.
	//        For each page to be mapped for a read/write segment,
	//        allocate a page in the parent temporarily at UTEMP,
	//        read() the appropriate portion of the file into that page
	//	  and/or use memset() to zero non-loaded portions.
	//	  (You can avoid calling memset(), if you like, if
	//	  page_alloc() returns zeroed pages already.)
	//        Then insert the page mapping into the child.
	//        Look at init_stack() for inspiration.
	//        Be sure you understand why you can't use read_map() here.
	//
	//     Note: None of the segment addresses or lengths above
	//     are guaranteed to be page-aligned, so you must deal with
	//     these non-page-aligned values appropriately.
	//     The ELF linker does, however, guarantee that no two segments
	//     will overlap on the same page; and it guarantees that
	//     PGOFF(ph->p_offset) == PGOFF(ph->p_va).
	//
	//   - Call sys_env_set_trapframe(child, &child_tf) to set up the
	//     correct initial eip and esp values in the child.
	//
	//   - Start the child process running with sys_env_set_status().

	// LAB 5: Your code here.
	// load the program image into BINARY
	if ((r = fdnum = open(prog, O_RDONLY)) < 0)
		return r;
	if ((r = file_size = file_get_size(fdnum)) < 0)
		return r;
	binary = (void *) BINARY;
	for (i = 0; i < file_size; i += BLKSIZE) {
		if ((r = read_map(fdnum, i, &va)) < 0)
			return r;
		if ((r = sys_page_map(0, va, 0, binary + i, PTE_P|PTE_U)) < 0)
			return r;
	}

	if ((r = child = sys_exofork()) < 0)
		return r;
	if (r == 0)
		return 0;

	// verify ELF and load the segments
	elf = (struct Elf *) binary;
	if (elf->e_magic != ELF_MAGIC)
		return -E_NOT_EXEC;
	ph = (struct Proghdr *) (binary + elf->e_phoff);
	eph = ph + elf->e_phnum;
	for (; ph < eph; ph++) {
		if (ph->p_type != ELF_PROG_LOAD)
			continue;
		if (ph->p_flags & ELF_PROG_FLAG_WRITE) {
			// prepare segment memory in our address space
			segment = (void *) SEGMENT;
			segment_end = segment +
				      ROUNDDOWN(ph->p_offset + ph->p_memsz - 1, PGSIZE) -
				      ROUNDDOWN(ph->p_offset, PGSIZE) + PGSIZE;
			for (va = segment; va < segment_end; va += PGSIZE) {
				if ((r = sys_page_alloc(0, va, PTE_P|PTE_U|PTE_W)) < 0)
					return r;
				memset(va, 0, PGSIZE);
			}
			// segment va diff in children's/our address space
			delta = ROUNDDOWN(ph->p_va, PGSIZE) - (uint32_t) segment;
			memcpy((void *) ph->p_va - delta,
			       binary + ph->p_offset, ph->p_filesz);
			perm = PTE_P | PTE_U | PTE_W;
		} else {
			segment = ROUNDDOWN(binary + ph->p_offset, PGSIZE);
			segment_end = ROUNDDOWN(binary + ph->p_offset + ph->p_filesz - 1,
						PGSIZE) + PGSIZE;
			delta = ROUNDDOWN(ph->p_va, PGSIZE) - (uint32_t) segment;
			perm = PTE_P | PTE_U;
		}
		// map segment memory into children's address space
		for (va = segment; va < segment_end; va += PGSIZE) {
			if ((r = sys_page_map(0, va, child, va + delta, perm)) < 0)
				return r;
			if ((r = sys_page_unmap(0, va)) < 0)
				return r;
		}
	}

	child_tf = envs[ENVX(child)].env_tf;
	child_tf.tf_eip = elf->e_entry;

	// clean up the mappings for the binary image
	for (i = 0; i < file_size; i += BLKSIZE)
		if ((r = sys_page_unmap(0, binary + i)) < 0)
			return r;

	// propagate PTE_SHARE pages
	perm = PTE_P | PTE_U | PTE_SHARE;
	for (va = (void *) 0; va < (void *) UTOP; va += PTSIZE) {
		if (!(vpd[VPD(va)] & PTE_P)) // page dir NA
			continue;
		for (va2 = ROUNDDOWN(va, PTSIZE);
		     va2 < MIN(ROUNDDOWN(va, PTSIZE) + PTSIZE, (void *) UTOP);
		     va2 += PGSIZE) {
			if ((vpt[VPN(va2)] & perm) != perm) // not SHARE page?
				continue;
			if ((r = sys_page_map(0, va2, child, va2,
					      vpt[VPN(va2)] & PTE_USER)) < 0)
				return r;
		}
	}

	if ((r = init_stack(child, argv, &child_tf.tf_esp)) < 0)
		return r;
	if ((r = sys_env_set_trapframe(child, &child_tf)) < 0)
		return r;
	if ((r = sys_env_set_status(child, ENV_RUNNABLE)) < 0)
		return r;
	return child;
}

// Spawn, taking command-line arguments array directly on the stack.
int
spawnl(const char *prog, const char *arg0, ...)
{
	return spawn(prog, &arg0);
}


// Set up the initial stack page for the new child process with envid 'child'
// using the arguments array pointed to by 'argv',
// which is a null-terminated array of pointers to null-terminated strings.
//
// On success, returns 0 and sets *init_esp
// to the initial stack pointer with which the child should start.
// Returns < 0 on failure.
static int
init_stack(envid_t child, const char **argv, uintptr_t *init_esp)
{
	size_t string_size;
	int argc, i, r;
	char *string_store;
	uintptr_t *argv_store;

	// Count the number of arguments (argc)
	// and the total amount of space needed for strings (string_size).
	string_size = 0;
	for (argc = 0; argv[argc] != 0; argc++)
		string_size += strlen(argv[argc]) + 1;

	// Determine where to place the strings and the argv array.
	// Set up pointers into the temporary page 'UTEMP'; we'll map a page
	// there later, then remap that page into the child environment
	// at (USTACKTOP - PGSIZE).
	// strings is the topmost thing on the stack.
	string_store = (char*) UTEMP + PGSIZE - string_size;
	// argv is below that.  There's one argument pointer per argument, plus
	// a null pointer.
	argv_store = (uintptr_t*) (ROUNDDOWN(string_store, 4) - 4 * (argc + 1));
	
	// Make sure that argv, strings, and the 2 words that hold 'argc'
	// and 'argv' themselves will all fit in a single stack page.
	if ((void*) (argv_store - 2) < (void*) UTEMP)
		return -E_NO_MEM;

	// Allocate the single stack page at UTEMP.
	if ((r = sys_page_alloc(0, (void*) UTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		return r;

	// Replace this with your code to:
	//
	//	* Initialize 'argv_store[i]' to point to argument string i,
	//	  for all 0 <= i < argc.
	//	  Also, copy the argument strings from 'argv' into the
	//	  newly-allocated stack page.
	//	  Hint: Copy the argument strings into string_store.
	//	  Hint: Make sure that argv_store uses addresses valid in the
	//	  CHILD'S environment!  The string_store variable itself
	//	  points into page UTEMP, but the child environment will have
	//	  this page mapped at USTACKTOP - PGSIZE.  Check out the
	//	  UTEMP2USTACK macro defined above.
	//
	//	* Set 'argv_store[argc]' to 0 to null-terminate the args array.
	//
	//	* Push two more words onto the child's stack below 'args',
	//	  containing the argc and argv parameters to be passed
	//	  to the child's umain() function.
	//	  argv should be below argc on the stack.
	//	  (Again, argv should use an address valid in the child's
	//	  environment.)
	//
	//	* Set *init_esp to the initial stack pointer for the child,
	//	  (Again, use an address valid in the child's environment.)
	//
	// LAB 5: Your code here.
	*(argv_store - 1) = (uintptr_t) UTEMP2USTACK(argv_store);
	*(argv_store - 2) = (uintptr_t) argc;
	for (i = 0; i < argc; i++) {
		argv_store[i] = (uintptr_t) UTEMP2USTACK(string_store);
		string_store = strcpy(string_store, argv[i]);
	}

	// Just set stack top to &argc; see _start at lib/entry.S.
	*init_esp = (uintptr_t) UTEMP2USTACK(argv_store - 2);

	// After completing the stack, map it into the child's address space
	// and unmap it from ours!
	if ((r = sys_page_map(0, UTEMP, child, (void*) (USTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W)) < 0)
		goto error;
	if ((r = sys_page_unmap(0, UTEMP)) < 0)
		goto error;

	return 0;

error:
	sys_page_unmap(0, UTEMP);
	return r;
}



