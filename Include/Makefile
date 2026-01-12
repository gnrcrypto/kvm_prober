# Makefile to build the web_probe kernel module and web_prober user-space tool.
# Usage:
#   make        - Build the kernel module and user tool (requires kernel headers for module build).
#   make clean  - Clean up build artifacts.
#
# Build instructions:
#  - Ensure you have a Linux kernel build environment available (KDIR pointing to kernel source or headers).
#  - By default, KDIR is set to /lib/modules/$(uname -r)/build for building against the running kernel.
#  - Running 'make' will produce web_probe_drv.ko (kernel module in ./kernel) and web_prober (user program).
#  - Load the kernel module with insmod or modprobe, then run ./web_prober with appropriate commands.
#
# Example:
#   make
#   sudo insmod kernel/web_probe_drv.ko
#   sudo ./user/web_prober readport 0x60
#   sudo ./user/web_prober httphead http://example.com
#

# Kernel build directory (override if needed)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Module source
obj-m := web_probe_drv.o
WEB_PROBE_SRC := kernel/web_probe_drv.c

# Userspace source
USER_SRC := user/web_prober.c
USER_BIN := user/web_prober

# Default target builds module and user tool
all: kernel_module user_tool

kernel_module:
	$(MAKE) -C $(KDIR) M=$(CURDIR) EXTRA_CFLAGS=-I$(CURDIR)/include modules

user_tool:
	$(CC) -Wall -I$(CURDIR)/include -o $(USER_BIN) $(USER_SRC)

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean || true
	$(RM) $(USER_BIN)
