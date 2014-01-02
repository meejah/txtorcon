FROM dockerbase-wheezy

RUN apt-get update
## FIXME would be Really Nice Indeed to grok this install list from
## ONE place. e.g. grep it out of README?

RUN apt-get install -y python-setuptools python-twisted python-ipaddr python-geoip graphviz
RUN apt-get install -y lsb-release

## fixme add tor repos?
RUN apt-get install -y tor

# upload our test code (actually, all our code)
# 'txtorcon' is a symbolic link since the dir for ADD has to be in the
# "context" (i.e. where the Dockerfile is or deeper)
ADD txtorcon /txtorcon

## to export a port into the host
##EXPOSE 9051

CMD ["/txtorcon/testcontainer/testcase_hidden_service_listener"]
## what's ENTRYPOINT? sometimes they use that instead?
