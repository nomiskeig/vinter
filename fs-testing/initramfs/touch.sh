#!/lib/ld-linux-x86-64.so.2 /bin/sh_dynamic 
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/mount_dynamic -tNOVA -oinit /dev/pmem0 /mnt
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/sync_dynamic
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 1
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/touch_dynamic /mnt/myfile 
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/sync_dynamic
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 2
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/sleep_dynamic 2
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/touch_dynamic /mnt/myfile 
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/sync_dynamic
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 3
