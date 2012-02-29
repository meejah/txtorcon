#!/usr/bin/env python

import os
import sys
import subprocess

print '''
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    <title>txtorcon</title>
    <link rel="stylesheet" type="text/css" media="all"
      href="style.css" title="Style" />
  </head>

  <body>
'''

print subprocess.check_output(['markdown', sys.argv[1]])

print '''
  </body>
</html>
'''
