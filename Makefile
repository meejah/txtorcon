.PHONY: test html counts coverage sdist clean install doc
.DEFAULT: test

test:
	trial --reporter=text test

install:
	python setup.py install

doc: docs/*.rst
	cd docs && make html
	-cp dist/txtorcon-0.9.0.tar.gz docs/_build/html

coverage:
	coverage run --source=txtorcon `which trial` test
	coverage -a -d annotated_coverage
	coverage report

# dang, this is a little annoying. maybe add a shell-script which
# looks for "coverage" or "python-coverage"??
coverage-debian:
	python-coverage run --source=txtorcon `which trial` test
	python-coverage -a -d annotated_coverage
	python-coverage report

pep8:
	find txtorcon/*.py test/*.py examples/*.py | xargs pep8 --ignore=E501

pep8count:
	find txtorcon/*.py test/*.py examples/*.py | xargs pep8 --ignore=E501 | wc -l

pyflakes:
	pyflakes txtorcon/ examples/ test/

pyflakescount:
	pyflakes txtorcon/ examples/ | wc -l

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

dist: dist/txtorcon-0.9.0.tar.gz.asc

sdist: setup.py 
	python setup.py sdist

dist/txtorcon-0.9.0-py27-none-any.whl:
	python setup.py bdist_wheel
dist/txtorcon-0.9.0-py27-none-any.whl.asc: dist/txtorcon-0.9.0-py27-none-any.whl
	gpg --verify dist/txtorcon-0.9.0-py27-none-any.whl.asc || gpg --no-version --detach-sign --armor --local-user meejah@meejah.ca dist/txtorcon-0.9.0-py27-none-any.whl

dist/txtorcon-0.9.0.tar.gz: sdist
dist/txtorcon-0.9.0.tar.gz.asc: dist/txtorcon-0.9.0.tar.gz
	gpg --verify dist/txtorcon-0.9.0.tar.gz.asc || gpg --no-version --detach-sign --armor --local-user meejah@meejah.ca dist/txtorcon-0.9.0.tar.gz

release: dist/txtorcon-0.9.0.tar.gz dist/txtorcon-0.9.0-py27-none-any.whl setup.py
	twine
##	python setup.py sdist upload --sign --identity=meejah@meejah.ca

venv:
	mkdir -p tmp
	cd tmp
	virtualenv --never-download --extra-search-dir=/usr/lib/python2.7/dist-packages/ venv
	@echo "created venv"
	@echo "see INSTALL for more information; to use:"
	@echo ". ./venv/bin/activate"
	@echo "pip install -r requirements.txt"
	@echo "pip install -r dev-requirements.txt"
	@echo "python examples/monitor.py"

html: docs/README.rst
	cd docs && make html
