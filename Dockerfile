FROM dockerbase-wheezy

RUN apt-get update
##RUN `awk '/BEGIN_INSTALL/,/END_INSTALL/' ./README.rst | /bin/grep apt-get | /bin/grep -v development`
## above fails when run via Docker
RUN apt-get install -y python-setuptools python-twisted python-ipaddr python-geoip graphviz tor

## we make our code available via a "container volume" (-v option to run)
## at /txtorcon

# this one just tells you to rtfm (use run.py)
CMD ["/txtorcon/integration/no_testcase"]
