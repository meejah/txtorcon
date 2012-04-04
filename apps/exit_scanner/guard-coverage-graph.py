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

## sort by guard bandwidth
success = open('succeeded-augmented.csv', 'r').readlines()[1:]
failed = open('failed-augmented.csv', 'r').readlines()[1:]
success.sort(lambda a, b: cmp(float(a.split(',')[6]), float(b.split(',')[6])))
failed.sort(lambda a, b: cmp(float(a.split(',')[6]), float(b.split(',')[6])))


# split into fields
success = map(lambda x: map(string.strip, x.split(',')), success)
failed = map(lambda x: map(string.strip, x.split(',')), failed)

# figure out our buckets
min_bw = min(float(failed[0][6]), float(success[0][6]))
max_bw = min(float(failed[-1][6]), float(success[-1][6]))
quarter = (max_bw - min_bw) / 4.0

quartiles = open('quartiles', 'w')
for i in range(4):
    bucketmin = i*quarter
    bucketmax = (i+1)*quarter

    succ = filter(lambda x: float(x[6]) >= bucketmin and float(x[6]) < bucketmax, success)
    fail = filter(lambda x: float(x[6]) >= bucketmin and float(x[6]) < bucketmax, failed)
    print len(succ),len(fail),"for bucket", bucketmin, bucketmax
    tot = float(len(succ) + len(fail))
    quartiles.write('%2.0fKiB %f %f %d %d %d 100' % (bucketmax/1024.0, 100.0*(len(succ)/tot), 100.0*(len(fail)/tot), len(succ), len(fail),
                                                       len(succ)+len(fail)))
    for reason in reasons:
        quartiles.write(' %f' % (100.0*(float(len(filter(lambda x: x[5].strip() == reason, fail))/tot))))
    quartiles.write('\n')
    
quartiles.close()

print "min, max BW:",min_bw,max_bw

commands = '''
#set term png large
set terminal pngcairo  transparent enhanced font "arial,14" size 1024, 512
set output "foo.png"

set key invert reverse Left outside
set title "Scanning Tor Guard->Exit Circuits"
set noytics
unset xtics
set style fill   solid 1.00 border lt -1
set grid nopolar
set grid noxtics nomxtics ytics nomytics noztics nomztics \
 nox2tics nomx2tics noy2tics nomy2tics nocbtics nomcbtics
set grid layerdefault   linetype 0 linewidth 1.000,  linetype 0 linewidth 1.000
set key invert samplen 4 spacing 1 width 0 height 0 
#set xtics border in scale 0,0 nomirror rotate by -45  offset character 0, 0, 0
set xtics  norangelimit font ",8"
set xtics   ()
set style data histogram
set style histogram rowstacked
set style fill solid border -1
set boxwidth 0.75
set grid y
set border 3

set ylabel "%% of total"
set yrange [0:100]
set xlabel "Exit Node bandwidth (KiB)\\nsplit into quartiles"

#plot "quartiles" using 3:xtic(1) ti "failure", '' using 2:ytic(4) ti "success", '' using 0:7:(stringcolumn(6)) ti '' with labels offset 0, -0.5##, '' using 0:2:(stringcolumn(4 + 5)) with labels nokey

set style line 4 linecolor rgb "#ff1100"
set style line 5 linecolor rgb "#aa0000"
set style line 6 linecolor rgb "#660000"
set style line 2 linecolor rgb "#11cc11"

plot "quartiles" using 8:xtic(1) ti "fail: %s" ls 4, '' using 9:xtic(1) ti "fail: %s" ls 5, '' using 10:xtic(1) ti "fail: %s" ls 6, '' using 2:ytic(4) ti "success" ls 2, '' using 0:7:(stringcolumn(6)) ti '' with labels offset 0, -0.5##, '' using 0:2:(stringcolumn(4 + 5)) with labels nokey
''' % (reasons.pop()[1:-1], reasons.pop()[1:-1], reasons.pop()[1:-1])


gnuplot = subprocess.Popen(['gnuplot'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
print gnuplot.communicate(commands)
