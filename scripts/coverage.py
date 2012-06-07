#!/usr/bin/env python

##
## this goes through the _trial_temp/coverage files looking for
## "txtorcon" ones and counts the covered and uncovered lines (not
## counting comments, etc) and spits out percentages.
##
## FIXME surely trial et al have a way to do this, but I didn't find
## one yet
##

import os

covered = 0
uncovered = 0

thedir = './_trial_temp/coverage'
for file in os.listdir(thedir):
    file = os.path.join(thedir,file)
    if 'txtorcon' in file and 'test' not in file:
        this_cover = 0
        this_uncover = 0
        for line in open(file,'r').readlines():
            if len(line) < 6:
                continue
            elif line[:6] == '>>>>>>':
                uncovered += 1
                this_uncover += 1
            elif line[5] == ':':
                int(line[:5])
                covered += 1
                this_cover += 1
        total_lines = this_cover + this_uncover
        cover_percent = (float(this_cover) / total_lines) * 100.0
        print '%65s: %03d of %03d (%02.1f%%)' % (file, this_cover, (total_lines), cover_percent)

print "  covered:",covered
print "uncovered:",uncovered
coverage = (float(covered)-uncovered)/covered * 100.0
print "%02.2f%% test coverage" % coverage
