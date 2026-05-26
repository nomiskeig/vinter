
MPKTRACER_DIR := /home/simon/projects/mpktracer
INITRAMFS_DEPS := \
	create-initramfs.sh \
	busybox \
	../../vinter_python/hypercall \
	../fs-dump/target/x86_64-unknown-linux-musl/release/fs-dump

	# this is renamed from like tracer_preload.so.1
MPK_DEPS := \
	$(MPKTRACER_DIR)/build-vinter/hypercall_mpk \
	$(MPKTRACER_DIR)/build-vinter/MPKTracerStarter \
	$(MPKTRACER_DIR)/build-vinter/libMPKTracerInject.so \
	#$(MPKTRACER_DIR)/kernel/tracer_module/tracer_module_vinter.ko 
#	../../MPKTracer/tests/collector_test/op_codes/test_slowdown_loops/test_module.ko

PWD := $(CURDIR)
default: initramfs.cpio.gz initramfs_pmfs.cpio.gz initramfs_mpk.cpio.gz
.PHONY: default


initramfs.cpio.gz: $(INITRAMFS_DEPS) 
	./create-initramfs.sh > $@

initramfs_mpk.cpio.gz: $(INITRAMFS_DEPS) $(MPK_DEPS)

	cd ../../MPKTracer/kernel/tracer_module/ && MODULE_NAME=tracer_module_vinter KERNEL_DIR="$(PWD)/../linux/MPKTracerNova_build" make
	mkdir -p mpk/{bin,lib,lib64}
	
	./copy-binary.sh $(MPKTRACER_DIR)/build-vinter/hypercall_mpk mpk
	./copy-binary.sh $(MPKTRACER_DIR)/build-vinter/MPKTracerStarter mpk
	./copy-binary.sh $(MPKTRACER_DIR)/build-vinter/libMPKTracerInject.so mpk
	#cp ../../MPKTracer/tests/collector_test/op_codes/test_slowdown_loops/test_module.ko mpk/bin
	./copy_system_bin.sh sh mpk
	./copy_system_bin.sh mount mpk
	./copy_system_bin.sh touch mpk
	./copy_system_bin.sh sleep mpk
	#./copy-binary.sh /usr/bin/perf mpk
	# copy over these libs into lib64 because the linker/shell requires them there
#	cp mpk/lib/libtinfo.so.6 mpk/lib64
#	cp mpk/lib/libc.so.6 mpk/lib64

	cp ../../MPKTracer/kernel/tracer_module/tracer_module_vinter.ko mpk/bin/tracer_module.ko
	cp ./hello_world.sh mpk/bin
	#cp /usr/bin/ld.so mpk/lib
	./copy_system_bin.sh echo mpk
	#cp /usr/bin/echo /tmp/echo_dynamic # this should replacse the statically linked version with a dynamically linked one so that we can use LD_PRELOAD
	#cp /tmp/echo_dynamic mpk/bin
	./copy_system_bin.sh sync mpk

	chmod +x mpk/bin/*
	chmod +x mpk/lib/*
	./create-initramfs.sh mpk > $@

# Newer busybox does not work with the old PMFS kernel.
initramfs_pmfs.cpio.gz: $(INITRAMFS_DEPS) busybox_pmfs
	BUSYBOX=./busybox_pmfs ./create-initramfs.sh > $@
	
initramfs_mainline.cpio.gz: $(INITRAMFS_DEPS)
	rm -rf initramfs_mainline
	mkdir -p initramfs_mainline/{bin,lib}
	ln -s lib initramfs_mainline/lib64
	./copy-binary.sh `which mkfs.ext4` initramfs_mainline
	./copy-binary.sh `which fsck.ext4` initramfs_mainline
	./copy-binary.sh `which mkfs.xfs` initramfs_mainline
	./copy-binary.sh `which xfs_repair` initramfs_mainline
	./create-initramfs.sh initramfs_mainline > $@

initramfs_zilpmem.cpio.gz: $(INITRAMFS_DEPS) ../zil-pmem/initramfs_zfs
	./create-initramfs.sh ../zil-pmem/initramfs_zfs > $@

busybox:
	curl -o $@ https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
	chmod +x $@

busybox_pmfs:
	curl -o $@ https://busybox.net/downloads/binaries/1.21.1/busybox-x86_64
	chmod +x $@
