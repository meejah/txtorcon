#!/bin/bash

pushd /tmp
tar zxvf ${1}/dist/txtorcon-${2}.tar.gz
cd txtorcon-${2}
make venv
. venv/bin/activate
pip install --editable .

## the actual "testing" part here
echo "testing doc build"
cd html
make clean
make html
cd ..
echo "testing endpoint plugins"
twistd web --port onion:80 --path .
sleep 5
cat twistd.log
echo "  killing"
kill `cat twistd.pid`
sleep 1
ls /tmp/tortmp*

## cleanup
deactivate
cd /tmp
rm -rf txtorcon-${2}
popd
