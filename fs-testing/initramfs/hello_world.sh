#!/bin/sh
#echo "test 1" && /lib/ld-linux-x86-64.so.3 --library-path /lib /bin/hypercall_mpk checkpoint 0  && echo "test" && sync && /bin/hypercall_mpk checkpoint 1 && echo HelloWorld > /mnt/myfile && /bin/hypercall_mpk checkpoint 2 && sync && hypercall_mpk /bin/checkpoint 3
printenv
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 0
sync
/lib/ld-linux-x86-64.so.2 --library-path /lib /bin/hypercall_mpk checkpoint 1
#echo HelloWorld > /mnt/myfile
#/bin/hypercall_mpk checkpoint 2 
#sync 
#hypercall_mpk /bin/checkpoint 3
