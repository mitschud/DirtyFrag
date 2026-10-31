obj-m += dfroot.o

# Upstream's diet step below is written as $(OBJCOPY), which the DDK container
# exports. Default it here so the recipe can never expand to an empty command
# (that would silently do nothing, or fail with 127) outside that image; a value
# from the environment still wins.
OBJCOPY ?= llvm-objcopy

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
