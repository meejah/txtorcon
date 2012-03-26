#!/usr/bin/env python

##
## saved from an ipython session, playing with figures from my only
## large-ish (~2000 routers) run. Why there were succeded + failed is
## 1997 and not 2000 needs to be figured out
##

import numpy
import string
import subprocess

print 'Analyzing "succeeded.csv" and "failed.csv"'
print

success = open('succeeded.csv', 'r').readlines()[1:]
failed = open('failed.csv', 'r').readlines()[1:]
total = len(success) + len(failed)

print "%d circuits attempted" % total
print "%d of %d failed; %f%% failed." % (len(failed), len(success), (100.0 * (float(len(failed))/total)))
print "average circuit build time:",sum(map(lambda x: float(x.split(',')[4]), success)) / float(len(success))

reasons = set()
[reasons.add(x) for x in map(lambda x: x.split(',')[5].strip(), failed)]
counts = {}
for x in reasons:
    counts[x] = 0
for line in failed:
    counts[line.split(',')[5].strip()] += 1
print "Reaons for failure:"
for (k,v) in counts.items():
    print "  %s: %f%%" % (k, 100.0 * (float(v) / len(failed)))
                                                    
print "average build time:",numpy.average(map(lambda x: float(x.split(',')[4]), success))
print "standard deviation:",numpy.std(map(lambda x: float(x.split(',')[4]),success))
#print filter(lambda x: x > (4.518+(2*2.245)), success)
#print filter(lambda x: float(x.split(',')[4]) > (4.518+(2*2.245)), success)

print "number of successful builds outside 2 stdard deviations:",len(filter(lambda x: float(x.split(',')[4]) > (4.518+(2*2.245)), success))
print "(that's %f percent)" % (100.0 * (float(len(filter(lambda x: float(x.split(',')[4]) > (4.518+(2*2.245)), success))) / float(total)))

##
## Make a gnuplot graph. there's a python gnuplot thing, I believe,
## but this way you get a gnuplot-standalone script too
##

## sort the results by circuit-build-time
success.sort(lambda a, b: cmp(float(a.split(',')[4]), float(b.split(',')[4])))
success.reverse()

failed.sort(lambda a, b: cmp(float(a.split(',')[4]), float(b.split(',')[4])))
failed.reverse()

## remap the data from comma-separated to space separated, and remove
## the headers to keep gnuplot happy
open('succeeded', 'w').write('\n'.join(map(lambda x: ' '.join(map(string.strip, x.split(','))), success)))
open('failed', 'w').write('\n'.join(map(lambda x: ' '.join(map(string.strip, x.split(','))), failed)))

commands = '''
set term png large
set output "foo.png"
set xlabel "router number (arbitrary)"
set ylabel "seconds to build circuit"
plot "succeeded" using 5 with lines, "failed" using 5 with lines
'''


gnuplot = subprocess.Popen(['gnuplot'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
print gnuplot.communicate(commands)
