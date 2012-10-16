.PHONY: test html counts coverage sdist clean install doc
.DEFAULT: test

test:
	trial --reporter=text txtorcon.test

install:
	python setup.py install

docs/README.rst: README
	pandoc -r markdown -w rst README -o docs/README.rst

doc: docs/*.rst docs/README.rst
	cd docs && make html
	cp dist/txtorcon-0.7.tar.gz docs/_build/html
	cp dist/txtorcon-0.6.tar.gz.sig docs/_build/html

coverage:
	trial --reporter=bwverbose --coverage txtorcon
	python scripts/coverage.py

clean:
	-rm -rf _trial_temp
	-rm -rf build
	-rm -rf dist
	-rm -rf html
	-rm MANIFEST
	-rm `find . -name \*.py[co]`
	-cd docs && make clean

counts:
	ohcount -s txtorcon/*.py

dist: dist/txtorcon-0.7.tar.gz.sig

sdist: setup.py 
	python setup.py sdist

dist/txtorcon-0.7.tar.gz: sdist
dist/txtorcon-0.7.tar.gz.sig: dist/txtorcon-0.7.tar.gz
	gpg --verify dist/txtorcon-0.7.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.7.tar.gz

release: dist/txtorcon-0.7.tar.gz.sig setup.py
	python setup.py sdist upload

html: docs/README.rst
	cd docs && make html
