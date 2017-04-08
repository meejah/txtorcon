#!/usr/bin/env python

## this runs all the integration tests under here, exiting right away
## if any one does.
## FIXME can't I [ab]use trial or unittest for this??

from __future__ import print_function

import os
import sys
import subprocess

base_path = os.path.split(os.path.realpath(sys.argv[0]))[0]
print("PATH", base_path)

for d in os.listdir(base_path):
    path = os.path.join(base_path, d, 'host_run')
    if os.path.exists(path):
        print()
        print("Running Test:", d)
        print(path)
        print()
        ret = subprocess.check_call([path])
        if ret:
            print()
            print("Test FAILED")
            sys.exit(ret)
        print()
        print("Test successful.")
        print()
sys.exit(0)
