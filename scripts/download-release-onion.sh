#!/bin/bash

# use this like:
#    download-release-onion.sh ${VERSION}
# ...to test that the hidden service contains the correct release

pushd /tmp
torsocks curl -O http://timaq4ygg2iegci7.onion/txtorcon-${1}.tar.gz || exit $?
torsocks curl -O http://timaq4ygg2iegci7.onion/txtorcon-${1}.tar.gz.asc || exit $?
gpg --verify txtorcon-${1}.tar.gz.asc || exit 1

torsocks curl -O http://timaq4ygg2iegci7.onion/txtorcon-${1}-py27-none-any.whl || exit $?
torsocks curl -O http://timaq4ygg2iegci7.onion/txtorcon-${1}-py27-none-any.whl.asc || exit $?
gpg --verify txtorcon-${1}.tar.gz.asc || exit 1

echo "Both binaries check out for version" ${1}
popd

