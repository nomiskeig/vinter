import re
import matplotlib.pyplot as plt
import numpy as np
print("reading data for normal")
time_before_regex = r"time before tracing: ([0-9\.]+)"
time_total_regex = r"Time for tracing total: ([0-9\.]+)"
time_after_trace_regex = r"time after tracing: ([0-9\.]+)"
time_done_regex= r"time done: ([0-9\.]+)"
with open("compare_res/test_hello-world/trace2img.log", "r") as file:
    content = file.read()
    res = re.search(time_before_regex, content)
    time_before_panda = float(res.group(1))
    
    res = re.search(time_done_regex, content)
    time_done_panda = float(res.group(1))

with open("compare_res/test_hello-world/vm.log") as file:
    content = file.read()
    res = re.search(time_total_regex, content)
    time_total_panda = float(res.group(1))

with open("compare_res/test_hello-world-mpk/vm.log") as file:
    content = file.read()
    res = re.search(time_before_regex, content)
    time_before_mpk = float(res.group(1))
    

    res = re.search(time_after_trace_regex, content)
    time_after_trace_mpk = float(res.group(1))

    res = re.search(time_done_regex, content)
    time_done_mpk = float(res.group(1))

    res = re.search(time_total_regex, content)
    time_total_mpk = float(res.group(1))


names = (
"PANDA in VM",
"MPK in VM",
    )

weight_counts = {
    "Boot time": np.array([time_before_panda,time_before_mpk]),
    "Time to trace": np.array([time_done_panda, time_after_trace_mpk]),
    "Time to copy trace bin": np.array([time_done_panda , time_done_mpk]),
    "Remaing time in wrapper": np.array([time_total_panda/1000, time_total_mpk/1000])

}

print(weight_counts)
width = 0.5

fig, ax = plt.subplots()
bottom = np.zeros(2)

heights = np.zeros(2)
plt.ylim((0,1.5))
for boolean, weight_count in weight_counts.items():

    height = weight_count - heights
    print("heights",heights)
    print("height", height)


    p = ax.bar( names, height, width, label=boolean, bottom=heights)

    heights += height 
    bottom += height

ax.set_title("Run time of the tracer")
ax.legend(loc="upper right")


plt.savefig("trace_times.pdf")
