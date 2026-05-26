#!/usr/bin/env bash

set -eu
#set -x
 
binary=${1:?need binary}
initramfs=${2:?need initramfs root}
needs_wrapper=${3:-}


#path=$(readlink -f "$(which $binary)")
if [ -n "$needs_wrapper" ]; then
echo "Copying wrapper for $binary"
path=/run/wrappers/bin/$binary
else 
path=/run/current-system/sw/bin/$binary
fi
echo "Copying $path" 
./copy-binary.sh "$path"  "$initramfs" true
