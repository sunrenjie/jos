#
# This makefile system follows the structuring conventions
# recommended by Peter Miller in his excellent paper:
#
#	Recursive Make Considered Harmful
#	http://aegis.sourceforge.net/auug97.pdf
#
OBJDIR := obj

ifdef LAB
SETTINGLAB := true
else
-include conf/lab.mk
endif

-include conf/env.mk

ifndef SOL
SOL := 0
endif
ifndef LABADJUST
LABADJUST := 0
endif

ifndef LABSETUP
LABSETUP := ./
endif


TOP = .

# Cross-compiler jos toolchain
#
# This Makefile will automatically use the cross-compiler toolchain
# installed as 'i386-jos-elf-*', if one exists.  If the host tools ('gcc',
# 'objdump', and so forth) compile for a 32-bit x86 ELF target, that will
# be detected as well.  If you have the right compiler toolchain installed
# using a different name, set GCCPREFIX explicitly by doing
#
#	make 'GCCPREFIX=i386-jos-elf-' gccsetup

# try to infer the correct GCCPREFIX
ifndef GCCPREFIX
GCCPREFIX := $(shell if i386-jos-elf-objdump -i 2>&1 | grep '^elf32-i386$$' >/dev/null 2>&1; \
	then echo 'i386-jos-elf-'; \
	elif objdump -i 2>&1 | grep 'elf32-i386' >/dev/null 2>&1; \
	then echo ''; \
	elif i386-elf-objdump -i 2>&1 | grep 'elf32-i386' >/dev/null 2>&1; \
	then echo 'i386-elf-'; \
	else echo "***" 1>&2; \
	echo "*** Error: Couldn't find an i386-*-elf version of GCC/binutils." 1>&2; \
	echo "*** Is the directory with i386-jos-elf-gcc in your PATH?" 1>&2; \
	echo "*** If your i386-*-elf toolchain is installed with a command" 1>&2; \
	echo "*** prefix other than 'i386-jos-elf-', set your GCCPREFIX" 1>&2; \
	echo "*** environment variable to that prefix and run 'make' again." 1>&2; \
	echo "*** To turn off this error, run 'gmake GCCPREFIX= ...'." 1>&2; \
	echo "***" 1>&2; exit 1; fi)
endif

# try to infer the correct QEMU
ifndef QEMU
%qemu qemu%: QEMU = $(shell if which qemu 2>/dev/null; then exit; \
        elif which qemu-system-i386 2>/dev/null; then exit; \
	else \
	qemu=/Applications/Q.app/Contents/MacOS/i386-softmmu.app/Contents/MacOS/i386-softmmu; \
	if test -x $$qemu; then echo $$qemu; exit; fi; fi; \
	echo "***" 1>&2; \
	echo "*** Error: Couldn't find a working QEMU executable." 1>&2; \
	echo "*** Is the directory containing the qemu binary in your PATH" 1>&2; \
	echo "*** or have you tried setting the QEMU variable in conf/env.mk?" 1>&2; \
	echo "***" 1>&2; exit 1)
endif

# try to generate a unique GDB port
GDBPORT	:= $(shell expr `id -u` % 5000 + 25000)

CC	:= $(GCCPREFIX)gcc -pipe
GCC_LIB := $(shell $(CC) -print-libgcc-file-name)
AS	:= $(GCCPREFIX)as
AR	:= $(GCCPREFIX)ar
LD	:= $(GCCPREFIX)ld
OBJCOPY	:= $(GCCPREFIX)objcopy
OBJDUMP	:= $(GCCPREFIX)objdump
NM	:= $(GCCPREFIX)nm

# Native commands
NCC	:= gcc $(CC_VER) -pipe
TAR	:= gtar
PERL	:= perl

# Compiler flags
# -fno-builtin is required to avoid refs to undefined functions in the kernel.
# Only optimize to -O1 to discourage inlining, which complicates backtraces.
CFLAGS	:= $(CFLAGS) $(DEFS) $(LABDEFS) -O -fno-builtin -I$(TOP) -MD -Wall -Wno-format -Wno-unused -Werror -gstabs -m32
CFLAGS += -fno-omit-frame-pointer
# -fno-tree-ch prevented gcc from sometimes reordering read_ebp() before
# mon_backtrace()'s function prologue on gcc version: (Debian 4.7.2-5) 4.7.2
CFLAGS += -fno-tree-ch

# Add -fno-stack-protector if the option exists.
CFLAGS += $(shell $(CC) -fno-stack-protector -E -x c /dev/null >/dev/null 2>&1 && echo -fno-stack-protector)

# Common linker flags
LDFLAGS := -m elf_i386

GCC_LIB := $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)

# Linker flags for JOS user programs
ULDFLAGS := -T user/user.ld

# Lists that the */Makefrag makefile fragments will add to
OBJDIRS :=

# Make sure that 'all' is the first target
all:

# Eliminate default suffix rules
.SUFFIXES:

# Delete target files if there is an error (or make is interrupted)
.DELETE_ON_ERROR:

# make it so that no intermediate .o files are ever deleted
.PRECIOUS: %.o $(OBJDIR)/boot/%.o $(OBJDIR)/kern/%.o \
	$(OBJDIR)/lib/%.o $(OBJDIR)/fs/%.o $(OBJDIR)/user/%.o

KERN_CFLAGS := $(CFLAGS) -DJOS_KERNEL -gstabs
USER_CFLAGS := $(CFLAGS) -DJOS_USER -gstabs

IMAGE = $(OBJDIR)/kern/kernel.img
ISOIMAGE = $(OBJDIR)/cdboot/jos.iso

# Include Makefrags for subdirectories
include boot/Makefrag
include kern/Makefrag

QEMUOPTS = -hda $(OBJDIR)/kern/kernel.img -serial mon:stdio -gdb tcp::$(GDBPORT)
QEMUOPTS += $(shell if $(QEMU) -nographic -help | grep -q '^-D '; then echo '-D qemu.log'; fi)
QEMUOPTS += $(QEMUEXTRA)

.gdbinit: .gdbinit.tmpl
	sed "s/localhost:1234/localhost:$(GDBPORT)/" < $^ > $@

gdb:
	gdb -x .gdbinit

pre-qemu: .gdbinit

qemu: $(IMAGE) pre-qemu
	$(QEMU) $(QEMUOPTS)

qemu-nox: $(IMAGE) pre-qemu
	@echo "***"
	@echo "*** Use Ctrl-a x to exit qemu"
	@echo "***"
	$(QEMU) -nographic $(QEMUOPTS)

qemu-gdb: $(IMAGE) pre-qemu
	@echo "***"
	@echo "*** Now run 'make gdb'." 1>&2
	@echo "***"
	$(QEMU) $(QEMUOPTS) -S

qemu-nox-gdb: $(IMAGE) pre-qemu
	@echo "***"
	@echo "*** Now run 'make gdb'." 1>&2
	@echo "***"
	$(QEMU) -nographic $(QEMUOPTS) -S

print-qemu:
	@echo $(QEMU)

print-gdbport:
	@echo $(GDBPORT)

BOCHSRC := .bochsrc

$(BOCHSRC): $(BOCHSRC).tmpl
	cat < $^ > $@

$(BOCHSRC)-gdb: $(BOCHSRC).tmpl
	cat < $^ > $@
	echo "gdbstub: enabled=1, port=$(GDBPORT), text_base=0, data_base=0, bss_base=0" >> $@

# XXX: explicit documentation/notice for the following:
# Now that support of internal debugger and that of gdb are mutually exclusive
# as configure options while compiling, and that bochs compiled with gdb
# support can still run in non-debugging mode, it is recommended to compile
# two versions of bochs with different names, based on configure options:
# 1. The one configured with --enable-debugger
#    This version has internal debugger enabled and is named 'bochs-dbg'
# 2. The one configured with --enable-gdb-stub
#    This version has gdb sub compiled and is named 'bochs'. GDB support is
#    turned on/off via 'gdbstub' option in configuration.

# TODO: duplicated code
ifndef BOCHS
bochs bochs-gdb: BOCHS = $(shell if which bochs 2>/dev/null; then exit; fi; \
	echo "*** Error: could not find executable bochs" 1>&2; \
	exit 1)

bochs-dbg: BOCHS = $(shell if which bochs-dbg 2>/dev/null; then exit; fi; \
	echo "*** Error: could not find executable bochs-dbg" 1>&2; \
	exit 1)
endif

# TODO: graceful exit when the bochs* executable is not found.

bochs: $(IMAGE) $(BOCHSRC)
	$(BOCHS) -q -f $(BOCHSRC)

bochs-dbg: $(IMAGE) $(BOCHSRC)
	$(BOCHS) -q -f $(BOCHSRC)

bochs-gdb: $(IMAGE) $(BOCHSRC)-gdb .gdbinit
	$(BOCHS) -q -f $(BOCHSRC)-gdb

# For deleting the build
clean:
	rm -rf $(OBJDIR)

realclean: clean
	rm -rf lab$(LAB).tar.gz bochs.out bochs.log

distclean: realclean
	rm -rf conf/gcc.mk

grade: $(LABSETUP)grade.sh
	$(V)$(MAKE) clean >/dev/null 2>/dev/null
	$(MAKE) all
	sh $(LABSETUP)grade.sh

handin: tarball
	@echo Please visit http://pdos.csail.mit.edu/cgi-bin/828handin
	@echo and upload lab$(LAB).tar.gz.  Thanks!

tarball: realclean
	tar cf - `ls -a | grep -v '^\.*$$' | grep -v '^CVS$$' | grep -v '^lab[0-9].*\.tar\.gz'` | gzip > lab$(LAB).tar.gz

# For test runs
run-%:
	$(V)rm -f $(OBJDIR)/kern/init.o $(IMAGE)
	$(V)$(MAKE) "DEFS=-DTEST=_binary_obj_user_$*_start -DTESTSIZE=_binary_obj_user_$*_size" $(IMAGE)
	bochs -q 'display_library: nogui'

xrun-%:
	$(V)rm -f $(OBJDIR)/kern/init.o $(IMAGE)
	$(V)$(MAKE) "DEFS=-DTEST=_binary_obj_user_$*_start -DTESTSIZE=_binary_obj_user_$*_size" $(IMAGE)
	bochs -q

# This magic automatically generates makefile dependencies
# for header files included from C source files we compile,
# and keeps those dependencies up-to-date every time we recompile.
# See 'mergedep.pl' for more information.
$(OBJDIR)/.deps: $(foreach dir, $(OBJDIRS), $(wildcard $(OBJDIR)/$(dir)/*.d))
	@mkdir -p $(@D)
	@$(PERL) mergedep.pl $@ $^

-include $(OBJDIR)/.deps

always:
	@:

.PHONY: all always \
	.gdbinit $(BOCHSRC) $(BOCHSRC)-gdb \
	handin tarball clean realclean clean-labsetup distclean grade labsetup
