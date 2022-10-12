obj-m := babyrootkit.o
babyrootkit-objs := rootkit.o hook.o

default:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod babyrootkit.ko

remove:
	sudo rmmod babyrootkit