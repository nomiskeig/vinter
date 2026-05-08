#!/usr/bin/env bash

set -eu

cd "$( dirname "${BASH_SOURCE[0]}" )"

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <kernel>"
	exit 1
fi

kernel=$1
build=${kernel}_build

if [[ ! -d "$build" ]]; then
	mkdir "$build"
fi
# always overwrite the config
ln -sf "../$kernel.config" "$build/.config"

cd "$kernel"

if [ -n "$IN_NIX_SHELL" ]; then
	nix develop --command make -j$(nproc) 0="../$build" bzImage

else 
make -j$(nproc) O="../$build" bzImage
fi


