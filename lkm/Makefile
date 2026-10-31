obj-m += dfroot.o

CFLAGS_dfroot.o := -Os -Qn -fno-addrsig -fno-asynchronous-unwind-tables \
                   -fno-unwind-tables

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) \
		ARCH=arm64 \
		LLVM=1 \
		modules
	$(OBJCOPY) --strip-unneeded \
	           -R .comment -R .note.gnu.property \
	           -R .note.Linux -R .note.GNU-stack \
	           -R .BTF -R .BTF.base -R .llvm_addrsig \
	           -R .hyp.text -R .hyp.bss -R .hyp.rodata -R .hyp.event_ids \
	           -R .hyp.patchable_function_entries -R .hyp.data \
	           dfroot.ko

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) \
		ARCH=arm64 \
		LLVM=1 \
		clean
	rm -f dfroot.lds

.PHONY: all clean
