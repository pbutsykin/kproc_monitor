CC = gcc

obj-m += vuln.o
obj-m += infector.o

objects = vpwn vpwn_fork vpwn_2fork vpwn_dnull vpwn_fread vpwn_kmod vpwn_umod_exec

all:$(objects)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

$(objects): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f $(objects)
