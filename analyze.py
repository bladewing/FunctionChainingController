import numpy as np
import matplotlib.pyplot as plt
import collections


fig = plt.figure()
filename = ["c39-fw.log", "c39-ddos.log", "c48-ips.log"]
col = ["r","g","b"]

y = list()
x = list()
a1 = dict()
for count in range(0,3):
    with open('../../daten/%s'%(filename[count])) as f:
        fw = f.read()

    daten = fw.split('\n')

    for r in range(0,len(daten)):
        row = daten[r]
        try:
            f = float(row[6:15])
            x.append(f)
            y.append(count + 1)
            a = dict()
            a1["%s"%(f)] = count+1
        except:
            continue

ax1 = fig.add_subplot(111)
ax1.set_xlabel("Time in seconds")
ax1.set_ylabel("Hosts")
od = collections.OrderedDict()
print(a1)
s_keys = sorted(a1, key=a1.__getitem__)
y=list()
for k in a1:
    y.append(k)
for key in sorted(y):
    od["%s"%key] = a1[key]
print(od)
x = list()
y = list()
for k in od:
    x.append(float(k))
    y.append(od[k])


ax1.scatter(x,y,c=y,s=5)
#ax1.step(x, y, 'k.', c="%s"%col[count], label="%s"%filename[count])


plt.show()