#!/usr/bin/env bash

set -eu
#set -x
 
binary=${1:?need binary}
initramfs=${2:?need initramfs root}
needs_wrapper=${3:-}

if [ -n "${IN_NIX_SHELL:-}" ]; then 
#path=$(readlink -f "$(which $binary)")
if [ -n "$needs_wrapper" ]; then
echo "Copying wrapper for $binary"
path=/run/wrappers/bin/$binary
else 
path=/run/current-system/sw/bin/$binary
fi
echo "Copying $path" 
./copy-binary.sh "$path"  "$initramfs" true
else
	path=$(whereis -b $binary | awk '{print $2}')
	dyn_path=/tmp/${path##*/}_dynamic
	echo $dyn_path
	cp "$path" $dyn_path
	./copy-binary.sh "$dyn_path" "$initramfs" true
fi
