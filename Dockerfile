FROM dockerbase-jessie

ADD docker-apt-tor /etc/apt/sources.list.d/tor.list
ADD docker-backports /etc/apt/sources.list.d/backports.list
ADD tor-deb-signing-key /root/tor-deb-signing-key

##RUN apt-get update
##RUN `awk '/BEGIN_INSTALL/,/END_INSTALL/' ./README.rst | /bin/grep apt-get | /bin/grep -v development`
## above fails when run via Docker

RUN apt-key add /root/tor-deb-signing-key
RUN apt-get update && apt-get install -y python-pip python-virtualenv python-dev tor
RUN pip install twisted ipaddress service-identity

# can we do this during build-time somehow?
# RUN pip install --editable /txtorcon

## we make our code available via a "container volume" (-v option to run)
## at /txtorcon

# this one just tells you to rtfm (use run.py)
CMD ["/txtorcon/integration/no_testcase"]
