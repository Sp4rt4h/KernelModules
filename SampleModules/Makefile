obj-m += printk.o
KDIR= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
