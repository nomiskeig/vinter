#!/usr/bin/env bash

set -eu
#set -x

# Usage: copy-binary.sh <binary> <initramfs root>

binary=${1:?need binary}
initramfs=${2:?need initramfs root}
change_name=${3:-}

if [ -n "$change_name" ]; then
	echo "Copying over $binary"
	cp --no-preserve=mode,ownership "$binary" "$initramfs/bin/$(basename $binary)_dynamic"
else
cp --no-preserve=mode,ownership "$binary" "$initramfs/bin/"
fi

# Copy libraries from host system.
if [ -n "$IN_NIX_SHELL" ]; then
ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs -I{} cp --no-preserve=mode,ownership --parents "{}" "$initramfs"

ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs -I{} cp --no-preserve=mode,ownership "{}" "$initramfs/lib"
else
ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs cp -t "$initramfs/lib"
fi

    
