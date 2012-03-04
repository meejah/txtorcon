.PHONY: test html counts coverage sdist clean install doc
.DEFAULT: test

test:
	trial --reporter=text txtorcon.test

install:
	python setup.py install

doc: dist/txtorcon-0.1.tar.gz.gpg README doc/*.rst
	-pandoc -r markdown -w rst README -o doc/README.rst
	cd doc && make html
	cp meejah.asc doc/_build/html/meejah.asc
	cp dist/txtorcon-0.1.tar.gz doc/_build/html
	cp dist/txtorcon-0.1.tar.gz.gpg doc/_build/html

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

counts:
	ohcount -s txtorcon/*.py

sdist:
	python setup.py sdist

dist/txtorcon-0.1.tar.gz: sdist
dist/txtorcon-0.1.tar.gz.gpg: dist/txtorcon-0.1.tar.gz
	gpg --verify dist/txtorcon-0.1.tar.gz.gpg || gpg --no-version --sign -u meejah@meejah.ca dist/txtorcon-0.1.tar.gz

html: dist/txtorcon-0.1.tar.gz.gpg README index.md
	-mkdir html
	python scripts/create-css.py > html/style.css
	cp meejah.asc html/meejah.asc
	python scripts/md-render.py index.md > html/index.html
	python scripts/md-render.py README > html/README.html
	cp dist/txtorcon-0.1.tar.gz html
	cp dist/txtorcon-0.1.tar.gz.gpg html
