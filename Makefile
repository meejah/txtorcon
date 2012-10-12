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
	cp dist/txtorcon-0.6.tar.gz docs/_build/html
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

dist: dist/txtorcon-0.6.tar.gz.sig

sdist: setup.py 
	python setup.py sdist

dist/txtorcon-0.1.tar.gz: sdist
dist/txtorcon-0.1.tar.gz.sig: dist/txtorcon-0.1.tar.gz
	gpg --verify dist/txtorcon-0.1.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.1.tar.gz

dist/txtorcon-0.2.tar.gz: sdist
dist/txtorcon-0.2.tar.gz.sig: dist/txtorcon-0.2.tar.gz
	gpg --verify dist/txtorcon-0.2.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.2.tar.gz

dist/txtorcon-0.3.tar.gz: sdist
dist/txtorcon-0.3.tar.gz.sig: dist/txtorcon-0.3.tar.gz
	gpg --verify dist/txtorcon-0.3.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.3.tar.gz

dist/txtorcon-0.4.tar.gz: sdist
dist/txtorcon-0.4.tar.gz.sig: dist/txtorcon-0.4.tar.gz
	gpg --verify dist/txtorcon-0.4.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.4.tar.gz

dist/txtorcon-0.5.tar.gz: sdist
dist/txtorcon-0.5.tar.gz.sig: dist/txtorcon-0.5.tar.gz
	gpg --verify dist/txtorcon-0.5.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.5.tar.gz

dist/txtorcon-0.6.tar.gz: sdist
dist/txtorcon-0.6.tar.gz.sig: dist/txtorcon-0.6.tar.gz
	gpg --verify dist/txtorcon-0.6.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.6.tar.gz

release: dist/txtorcon-0.6.tar.gz.sig setup.py
	python setup.py sdist upload

html: dist/txtorcon-0.6.tar.gz.sig README index.md
	-mkdir html
	python scripts/create-css.py > html/style.css
	cp meejah.asc html/meejah.asc
	python scripts/md-render.py index.md > html/index.html
	python scripts/md-render.py README > html/README.html
	cp dist/txtorcon-0.6.tar.gz html
	cp dist/txtorcon-0.6.tar.gz.sig html
