#include <inc/x86.h>
#include <inc/elf.h>

/**********************************************************************
 * This a dirt simple boot loader, whose sole job is to boot
 * an elf kernel image from the first IDE hard disk.
 *
 * DISK LAYOUT
 *  * This program(boot.S and main.c) is the bootloader.  It should
 *    be stored in the first sector of the disk.
 * 
 *  * The 2nd sector onward holds the kernel image.
 *	
 *  * The kernel image must be in ELF format.
 *
 * BOOT UP STEPS	
 *  * when the CPU boots it loads the BIOS into memory and executes it
 *
 *  * the BIOS intializes devices, sets of the interrupt routines, and
 *    reads the first sector of the boot device(e.g., hard-drive) 
 *    into memory and jumps to it.
 *
 *  * Assuming this boot loader is stored in the first sector of the
 *    hard-drive, this code takes over...
 *
 *  * control starts in bootloader.S -- which sets up protected mode,
 *    and a stack so C code then run, then calls cmain()
 *
 *  * cmain() in this file takes over, reads in the kernel and jumps to it.
 **********************************************************************/

#define SECTSIZE	512
// Our ELF header needs 0x1000 bytes. Since FreeBSD cdboot.s loads kernel to
// buffer at 0x9000, our cdboot binary starts at 0x7c00 and extends beyond
// 0x8000, the address nearest to ideal will be 0x6000.
#define ELFHDR		((struct Elf *) 0x6000)

void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);

void
cmain(void)
{
	struct Proghdr *ph, *eph;

	// read 1st page off disk
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);

	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
		readseg(ph->p_va, ph->p_memsz, ph->p_offset);

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry & 0xFFFFFF))();

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}

void *
memmove(void *dst, const void *src, size_t n)
{
	const char *s;
	char *d;
	
	s = src;
	d = dst;
	if (s < d && s + n > d) {
		s += n;
		d += n;
		while (n-- > 0)
			*--d = *--s;
	} else
		while (n-- > 0)
			*d++ = *s++;

	return dst;
}

// Read 'count' bytes at 'offset' from kernel into virtual address 'va'.
// Might copy more than asked
// TODO: dirty method with the help of external CD reader; improvements needed.
void
readseg(uint32_t va, uint32_t count, uint32_t offset)
{
	uint32_t end_va;
	extern int buffer_kernel;

	va &= 0xFFFFFF; // clear the kernel virtual address relocating bits
	memmove((void *)va, (void *)(buffer_kernel + offset), count);
}

