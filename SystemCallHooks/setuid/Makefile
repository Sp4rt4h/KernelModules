obj-m += Hooksetuid.o
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	rm -f *.mod.c *.ko *.o
