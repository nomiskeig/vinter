#!/usr/bin/env bash

kernel=${1:?need kernel}
mpk=${2:?need mpk dir}
mkfile="$kernel/arch/x86/mpktracer/Makefile"

files=("allocator" "collector" "displaced_instructions" "new_trampolines" "register" "globals" "instruction" "logging" "shared" "new_logging" "rdtsc" "post" "pre" "trampoline" "signal_handler2")

function copy_inject_file() {
	echo "Copying $1"
	cp "$mpk/inject/src/shared/$1.c" "$kernel/arch/x86/mpktracer"
	cp "$mpk/inject/include/MPKTracer/$1.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
}


echo "ccflags-y := -mxsave -fno-stack-protector -O1 -std=gnu11" > "$mkfile"

mkdir -p "$kernel"/arch/x86/mpktracer/MPKTracer
mkdir -p "$kernel"/arch/x86/mpktracer/MPKTracer/options
mkdir -p "$kernel"/arch/x86/mpktracer/trampolines
echo "ccflags-y += -I$kernel/arch/x86/mpktracer/MPKTracer" >> "$mkfile"
echo "obj-y += Zydis.o" >> "$mkfile"
echo "obj-y += tracer.o" >> "$mkfile"
echo "obj-y += vmalloc_for_tramp.o" >> "$mkfile"

cp "$mpk/inject/include/MPKTracer/config.old.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/include/MPKTracer/pthread_handling.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/include/MPKTracer/inline_handlers.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/include/MPKTracer/regs.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/include/MPKTracer/logging_defs.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/include/MPKTracer/collect.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/include/MPKTracer/timing_hooks.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp  "$mpk/inject/include/MPKTracer/options/protect_install_mode.h" "$kernel/arch/x86/mpktracer/MPKTracer/options"
cp  "$mpk/inject/include/MPKTracer/options/protect_toggle_mode.h" "$kernel/arch/x86/mpktracer/MPKTracer/options"
cp  "$mpk/inject/include/MPKTracer/options/trampoline_install_mode.h" "$kernel/arch/x86/mpktracer/MPKTracer/options"
cp "$mpk/shared/include/MPKTracer/print.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/include/MPKTracer/logging_functions.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$kernel/arch/x86/include/Zydis.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$kernel/arch/x86/mpktracer/config.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$kernel/arch/x86/mpktracer/vmalloc_for_tramp.h" "$kernel/arch/x86/mpktracer/MPKTracer/"
cp "$mpk/inject/src/shared/trampolines/shared.c" "$kernel/arch/x86/mpktracer/trampolines/"
echo "obj-y += trampolines/shared.o" >> "$mkfile"
cp "$mpk/inject/src/options/protect_toggle_mode/inline.c" "$kernel/arch/x86/mpktracer/"
echo "obj-y += inline.o" >> "$mkfile"

cp "$mpk/inject/src/options/trampoline_install_mode/inline.c" "$kernel/arch/x86/mpktracer/trampoline_install_inline.c"
echo "obj-y += trampoline_install_inline.o" >> "$mkfile"
cp "$mpk/inject/src/options/protect_install_mode/ptrace.c" "$kernel/arch/x86/mpktracer/"
echo "obj-y += ptrace.o" >> "$mkfile"
for file in ${files[@]}
do
	copy_inject_file "$file"
	echo "obj-y += $file.o" >> "$mkfile"
done


