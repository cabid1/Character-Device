obj-m += hello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


unmount_memefs:
	sudo fusermount -u /tmp/memefs

mount_memefs:
	./memefs myfilesystem.img /tmp/memefs

build_memefs:
	gcc -Wall memefs.c `pkg-config fuse3 --cflags --libs` -o memefs

build_mkmemefs:
	gcc -o mkmemefs mkmemefs.c

create_memefs_img:
	./mkmemefs myfilesystem.img "MYVOLUME"
