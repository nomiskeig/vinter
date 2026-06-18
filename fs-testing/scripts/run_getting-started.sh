#!/usr/bin/env bash
set -eu -o pipefail

script=$0
scriptdir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=$scriptdir/../..
results=results_getting-started

rm -rf "$results"
mkdir -p "$results"/{vinter_python,vinter_rust}

vm=${1:-"vm_nova"}
if [ "$vm" = "vm_nova" ]; then
test=test_hello-world
else 
test=test_hello-world-mpk
fi
#vms=("vm_nova")
vms=("${vm}")

# Analysis with vinter_rust
for vm in "${vms[@]}"; do
  echo "Running vinter_rust with test $test on $vm..."
  "$base/target/release/vinter_trace2img" analyze --output-dir "$results/vinter_rust" \
    "$scriptdir/$vm.yaml" "$scriptdir/$test.yaml"
done
