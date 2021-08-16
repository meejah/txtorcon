#!/bin/bash

# use this like:
#    download-release-onion.sh ${VERSION}
# ...to test that the hidden service contains the correct release

set -x
pushd /tmp
torsocks curl -O http://fjblvrw2jrxnhtg67qpbzi45r7ofojaoo3orzykesly2j3c2m3htapid.onion/txtorcon-${1}.tar.gz || exit $?
torsocks curl -O http://fjblvrw2jrxnhtg67qpbzi45r7ofojaoo3orzykesly2j3c2m3htapid.onion/txtorcon-${1}.tar.gz.asc || exit $?
gpg --verify txtorcon-${1}.tar.gz.asc || exit 1

torsocks curl -O http://fjblvrw2jrxnhtg67qpbzi45r7ofojaoo3orzykesly2j3c2m3htapid.onion/txtorcon-${1}-py2.py3-none-any.whl || exit $?
torsocks curl -O http://fjblvrw2jrxnhtg67qpbzi45r7ofojaoo3orzykesly2j3c2m3htapid.onion/txtorcon-${1}-py2.py3-none-any.whl.asc || exit $?
gpg --verify txtorcon-${1}-py2.py3-none-any.whl.asc || exit 1

echo "Both binaries check out for version" ${1}
popd

