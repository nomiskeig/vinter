
INITRAMFS_DEPS := \
	create-initramfs.sh \
	busybox \
	../../vinter_python/hypercall \
	../fs-dump/target/x86_64-unknown-linux-musl/release/fs-dump

MPK_DEPS := \
	../../MPKTracer/out/hypercall_mpk \
	../../MPKTracer/out/libZydis.so.4-no_libc \
	../../MPKTracer/out/starter \
	../../MPKTracer/out/tracer_preload.so.1 \
	../../MPKTracer/kernel/tracer_module/tracer_module_vinter.ko
	

PWD := $(CURDIR)
default: initramfs.cpio.gz initramfs_pmfs.cpio.gz initramfs_mpk.cpio.gz
.PHONY: default

../../MPKTracer/kernel/tracer_module/tracer_module_vinter.ko:
	(cd ../../MPKTracer/kernel/tracer_module/ && MODULE_NAME=tracer_module_vinter KERNEL_DIR="$(PWD)/../linux/MPKTracerNova_build" make)

initramfs.cpio.gz: $(INITRAMFS_DEPS) 
	./create-initramfs.sh > $@
	
initramfs_mpk.cpio.gz: $(INITRAMFS_DEPS) $(MPK_DEPS)
	mkdir -p mpk/{bin,lib}
	./copy-binary.sh ../../MPKTracer/out/hypercall_mpk mpk
	./copy-binary.sh ../../MPKTracer/out/libZydis.so.4-no_libc mpk
	./copy-binary.sh ../../MPKTracer/out/starter mpk
	./copy-binary.sh ../../MPKTracer/out/tracer_preload.so.1 mpk
	cp ../../MPKTracer/kernel/tracer_module/tracer_module_vinter.ko mpk/bin/tracer_module.ko
	cp /usr/bin/ld.so mpk/lib
	cp /usr/bin/ldd mpk
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
