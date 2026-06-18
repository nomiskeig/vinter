# Example: normalize all files into tmp dirs, stripping matches
mkdir -p norm norm_mpk
rm norm/*
echo " Removed norm"
rm norm_mpk/*
ls norm
for f in test_hello-world/semantic_states/*; do
    sed -E -e 's/\"st_atim_sec\":.*//' -e 's/\"st_mtim_sec\":.*//' -e 's/\"st_ctim_sec\":.*//' "$f" > "norm/$(basename "$f")"
done
for f in test_hello-world-mpk/semantic_states/*; do
    sed -E -e 's/\"st_atim_sec\":.*//' -e 's/\"st_mtim_sec\":.*//' -e 's/\"st_ctim_sec\":.*//' "$f" > "norm_mpk/$(basename "$f")"
done
echo "Result"
fdupes -R -m norm norm_mpk


