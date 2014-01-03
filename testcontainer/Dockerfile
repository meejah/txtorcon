FROM dockerbase-wheezy

## FIXME would be Really Nice Indeed to grok this install list from
## ONE place. e.g. grep it out of README?
RUN apt-get install -y python-setuptools python-twisted python-ipaddr python-geoip graphviz tor

# upload our test code (actually, all our code)
# 'txtorcon' is a symbolic link since the dir for ADD has to be in the
# "context" (i.e. where the Dockerfile is or deeper). the symlink
# goes to /tmp/txtorcon, which was rsync'd with our code by the Makefile
ADD txtorcon /txtorcon

# this one just tells you to rtfm (use run.py)
CMD ["/txtorcon/integration/no_testcase"]
