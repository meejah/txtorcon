#!/usr/bin/env python

##
## saved from an ipython session, playing with figures from my only
## large-ish (~2000 routers) run. Why there were succeded + failed is
## 1997 and not 2000 needs to be figured out
##

import numpy
import string
import subprocess

routers = open('exitbandwidth.data', 'r').readlines()[1:]
routers.sort(lambda a, b: cmp(int(a.split()[1]), int(b.split()[1])))
routers.reverse()
open('data', 'w').write('\n'.join(routers))

routers = open('guardbandwidth.data', 'r').readlines()[1:]
routers.sort(lambda a, b: cmp(int(a.split()[1]), int(b.split()[1])))
open('data2', 'w').write('\n'.join(routers))

count = 0
for line in routers:
    name, bw = line.split()
    count += 1
    if int(bw) < 1024:
        print count
        break
print routers[200]

commands = '''
#set term png large
set terminal pngcairo transparent enhanced font "arial,14" size 1024, 512
set output "bar.png"

set title "Tor Exit and Guard Bandwidths\\nExits are sorted decending, Guards vice-versa"
set xlabel "Router"
set ylabel "Bandwidth (bytes)"
plot 'data' using 2 with impulses title "Exit Router bandwidth", 'data2' using 2 with impulses title "Guard Router bandwidth"
'''

gnuplot = subprocess.Popen(['gnuplot'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
print gnuplot.communicate(commands)
