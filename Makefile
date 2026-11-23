obj-m += src/main.o

# Find kernel build directory (checks running kernel or highest installed version)
KDIR ?= $(shell if [ -d /lib/modules/$$(uname -r)/build ]; then echo /lib/modules/$$(uname -r)/build; else echo /usr/lib/modules/$$(ls -1 /usr/lib/modules | tail -n 1)/build; fi)
PWD  := $(CURDIR)

all:
	@echo "Building kernel module using KDIR=$(KDIR)"
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@echo "Cleaning kernel module build artifacts"
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f src/*.o src/.*.cmd src/*.mod src/*.mod.c src/*.mod.o

.PHONY: all clean
