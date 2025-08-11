#!/lib/ld-linux-x86-64.so.2 /bin/sh_dynamic 
# on the testing vm, this invokes the LD_PRELOAD everytime, but it seems like this is not the case here. It could be that ubuntu configures their shell differently, idk
# -> this is because LD_PRELOAD only works on dynamically linked binaries 
# we first mount the file system, this is normally done in the vm_kernel file but its not traced then in our case
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/mount_dynamic -tNOVA -oinit /dev/pmem0 /mnt
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/sync_dynamic
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 0
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/sync_dynamic
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 1
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/echo_dynamic HelloWorld > /mnt/myfile
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 2
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/sync_dynamic
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 3
