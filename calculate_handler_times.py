import csv
import numpy as py
import re
from itertools import batched


runtimes = []
with open("/home/sgiek/times_all_handlers.txt", "r") as file:
    for row in file:
        if not row.startswith("Line: Handler: "):
            continue

        num = re.findall(r'\d+', row);
        runtimes.append(int(num[0]))


print(len(runtimes))

average = py.average(runtimes)
print(average)
m = [0.75, 0.8, 0.85, 0.9, 0.95, 1, 1.05, 1.1, 1.15, 1.2, 1.5, 2, 3, 4, 5, 6, 8, 10];
cap= {} 
buf2 = {}
for i in range(0, len(m)):
    buf2[i] = 0;
buf2[23] =0;
count = 0
for i in range(0, len(m)):
    cap[i] = average * m[i]
print(cap)
found = False;
for i in range(0, len(runtimes)):
    found = False;
    for j in range(0, len(m)):
        if runtimes[i] < cap[j]:
            buf2[j] += 1
            found = True
            break;
    if not found:
	    buf2[23] += 1;
count = 0;
for i in range(0, len(m)):
    count += buf2[i];
    print(f"{m[i]:.2f}xavg ({cap[i]:.6f} cycles) {buf2[i]} \t-> {count/len(runtimes):.3f}%");

print(f"Rest: {buf2[23]}\n");
    

