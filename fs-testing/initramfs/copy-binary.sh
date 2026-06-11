#!/usr/bin/env bash

set -eu
#set -x

# Usage: copy-binary.sh <binary> <initramfs root>

binary=${1:?need binary}
initramfs=${2:?need initramfs root}
change_name=${3:-}


# Copy libraries from host system.
if [ -n "${IN_NIX_SHELL:-}" ]; then

if [ -n "$change_name" ]; then
	echo "Copying over $binary"
	cp --no-preserve=mode,ownership "$binary" "$initramfs/bin/$(basename $binary)_dynamic"
else
cp --no-preserve=mode,ownership "$binary" "$initramfs/bin/"
fi
ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs -I{} cp --no-preserve=mode,ownership --parents "{}" "$initramfs"

ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs -I{} cp --no-preserve=mode,ownership "{}" "$initramfs/lib"
else
	echo "Copying over $binary"
	cp "$binary" "$initramfs/bin/"
ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs cp -t "$initramfs/lib"
# copy things to both lib and lib64 because some things need to be in lib64 it seems
ldd "$binary" | \
  awk '/ => \// { print $3 } /ld-linux/ { print $1 }' | \
  xargs cp -t "$initramfs/lib64"
fi

    
