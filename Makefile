
obj-m := myhook_add_tcp_option.o                #the module name need generate
modules-objs:= myhook.o                         #the object file needed

KDIR := /lib/modules/`uname -r`/build
PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o .* .cmd *.ko *.mod.c .tmp_versions

