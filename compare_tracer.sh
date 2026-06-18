#!/usr/bin/env bash

basedir=$(pwd)
# First, the original tracer based on pandas

echo "Running with PANDAS"
./build-vinter.sh
cd "$basedir"/fs-testing/scripts
./run_getting-started.sh
rm -r "${basedir}/compare_res/test_hello-world"
cp -r results_getting-started/vinter_rust/vm_nova/test_hello-world "$basedir"/compare_res


cd "$basedir"
echo "Running with MPKTracer"

./build-vinter.sh "--features tracer_mpk"
cd "$basedir"/fs-testing/scripts
./run_getting-started.sh "vm_MPKTracerNOVA"
rm -r "${basedir}/compare_res/test_hello-world-mpk"
cp -r results_getting-started/vinter_rust/vm_MPKTracerNOVA/test_hello-world-mpk "$basedir"/compare_res

cd "$basedir"/compare_res
./compare.sh
