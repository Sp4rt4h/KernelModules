obj-m := Hooksetuid.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -c $(KDIR) SUBDIRS=$(PWD) modules
