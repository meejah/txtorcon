FROM dockerbase-wheezy

## FIXME would be Really Nice Indeed to grok this install list from
## ONE place. e.g. grep it out of README?
RUN apt-get update
RUN apt-get install -y python-setuptools python-twisted python-ipaddr python-geoip graphviz tor

## we make our code available via a "container volume" (-v option to run)
## at /txtorcon

# this one just tells you to rtfm (use run.py)
CMD ["/txtorcon/integration/no_testcase"]
