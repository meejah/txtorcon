.PHONY: test html counts coverage sdist clean install doc integration diagrams
default: test
VERSION = 21.0.0

test:
	PYTHONPATH=. trial --reporter=text test

tox:
	tox -i http://localhost:3141/root/pypi

diagrams:
	automat-visualize --image-directory ./diagrams --image-type png txtorcon

diagrams:
	automat-visualize --image-directory ./diagrams --image-type png txtorcon

# see also http://docs.docker.io/en/latest/use/baseimages/
dockerbase-wheezy:
	@echo 'Building a minimal "wheezy" system.'
	@echo "This may take a while...and will consume about 240MB when done."
	debootstrap wheezy dockerbase-wheezy

dockerbase-wheezy-image: dockerbase-wheezy
	@echo 'Importing dockerbase-wheezy into docker'
	tar -C dockerbase-wheezy -c . | docker import - dockerbase-wheezy
	docker run dockerbase-wheezy cat /etc/issue

# see also http://docs.docker.io/en/latest/use/baseimages/
dockerbase-jessie:
	@echo 'Building a minimal "jessie" system.'
	@echo "This may take a while...and will consume about 240MB when done."
	debootstrap jessie dockerbase-jessie

dockerbase-jessie-image: dockerbase-jessie
	@echo 'Importing dockerbase-jessie into docker'
	tar -C dockerbase-jessie -c . | docker import - dockerbase-jessie
	docker run dockerbase-jessie cat /etc/issue

txtorcon-tester: Dockerfile dockerbase-jessie-image
	@echo "Creating a Docker.io container"
	docker build --rm -q -t txtorcon-tester ./

integration: ## txtorcon-tester
	python integration/run.py

install:
	sudo apt-get install python-setuptools python-twisted python-ipaddress graphviz
	python setup.py install

doc: docs/*.rst
	cd docs && make html
	-cp dist/txtorcon-${VERSION}.tar.gz docs/_build/html

coverage:
	PYTHONPATH=. coverage run --source=txtorcon `which trial` test
	cuv graph

htmlcoverage:
	coverage run --source=txtorcon `which trial` test
	coverage report --show-missing
	coverage html  # creates htmlcov/
	sensible-browser htmlcov/index.html

# dang, this is a little annoying. maybe add a shell-script which
# looks for "coverage" or "python-coverage"??
coverage-debian:
	python-coverage run --source=txtorcon `which trial` test
	python-coverage -a -d annotated_coverage
	python-coverage report

pep8: txtorcon/*.py test/*.py examples/*.py
	pycodestyle --ignore=E501 $^

pep8count:
	pycodestyle --ignore=E501,E265 $^ | wc -l

pyflakes:
	pyflakes txtorcon/ examples/ test/

pyflakescount:
	pyflakes txtorcon/ examples/ | wc -l

clean:
	-rm twisted/plugins/dropin.cache
	-rm -rf _trial_temp
	-rm -rf build
	-rm -rf dist
	-rm -rf html
	-rm MANIFEST
	-rm `find . -name \*.py[co]`
	-cd docs && make clean
	-rm -rf dockerbase-jessie
	-docker rmi txtorcon-tester
	-docker rmi dockerbase-jessie

counts:
	ohcount -s txtorcon/*.py

test-release: dist
	./scripts/test-release.sh $(shell pwd) ${VERSION}

dist: dist/txtorcon-${VERSION}-py2.py3-none-any.whl dist/txtorcon-${VERSION}.tar.gz

dist-sigs: dist/txtorcon-${VERSION}-py2.py3-none-any.whl.asc dist/txtorcon-${VERSION}.tar.gz.asc

sdist: setup.py
	python setup.py check
	python setup.py sdist

dist/txtorcon-${VERSION}-py2.py3-none-any.whl:
	python setup.py check
	python setup.py bdist_wheel --universal

dist/txtorcon-${VERSION}-py2.py3-none-any.whl.asc: dist/txtorcon-${VERSION}-py2.py3-none-any.whl
	gpg --verify dist/txtorcon-${VERSION}-py2.py3-none-any.whl.asc || gpg --pinentry loopback --no-version --detach-sign --armor --local-user meejah@meejah.ca dist/txtorcon-${VERSION}-py2.py3-none-any.whl

dist/txtorcon-${VERSION}.tar.gz: sdist
dist/txtorcon-${VERSION}.tar.gz.asc: dist/txtorcon-${VERSION}.tar.gz
	gpg --verify dist/txtorcon-${VERSION}.tar.gz.asc || gpg --pinentry loopback --no-version --detach-sign --armor --local-user meejah@meejah.ca dist/txtorcon-${VERSION}.tar.gz

release:
	twine upload -r pypi -c "txtorcon v${VERSION} tarball" dist/txtorcon-${VERSION}.tar.gz dist/txtorcon-${VERSION}.tar.gz.asc
	twine upload -r pypi -c "txtorcon v${VERSION} wheel" dist/txtorcon-${VERSION}-py2.py3-none-any.whl dist/txtorcon-${VERSION}-py2.py3-none-any.whl.asc


venv:
	virtualenv --never-download --extra-search-dir=/usr/lib/python2.7/dist-packages/ venv
	@echo "created venv"
	@echo "see INSTALL for more information; to use:"
	@echo ". ./venv/bin/activate"
	@echo "pip install -r requirements.txt"
	@echo "pip install -r dev-requirements.txt"
	@echo "python examples/monitor.py"

html: docs/*.rst
	cd docs && make html

html-server: html
	twistd -n web --path docs/_build/html --port tcp:9999:interface=localhost
