#!/bin/sh
# see https://stackoverflow.com/questions/4642191/read-line-by-line-in-bash-script
while IFS= read -r cmd; do
	echo "found new line"
	if [[ "$cmd" == *"Successfully booted vm"* ]]; then
		echo "matched"
		exit 1
	fi
	printf '%s\n' "$cmd"
	
done < "$1"pwd
