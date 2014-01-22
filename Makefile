.PHONY: test html counts coverage sdist clean install doc integration
default: test


test:
	trial --reporter=text test

# see also http://docs.docker.io/en/latest/use/baseimages/
dockerbase-wheezy:
	@echo 'Building a minimal "wheezy" system.'
	@echo "This may take a while...and will consume about 240MB when done."
	debootstrap wheezy dockerbase-wheezy

dockerbase-wheezy-image: dockerbase-wheezy
	@echo 'Importing dockerbase-wheezy into docker'
	tar -C dockerbase-wheezy -c . | docker import - dockerbase-wheezy
	docker run dockerbase-wheezy cat /etc/issue

txtorcon-tester: Dockerfile dockerbase-wheezy-image
	@echo "Creating a Docker.io container"
	docker build -rm -q -t txtorcon-tester ./

integration: ## txtorcon-tester
	python integration/run.py

install:
	python setup.py install

doc: docs/*.rst
	cd docs && make html
	-cp dist/txtorcon-0.9.2.tar.gz docs/_build/html

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
	-rm -rf dockerbase-wheezy
	-docker rmi txtorcon-tester
	-docker rmi dockerbase-wheezy

counts:
	ohcount -s txtorcon/*.py

dist: dist/txtorcon-0.9.2-py27-none-any.whl.asc dist/txtorcon-0.9.2.tar.gz.asc

sdist: setup.py 
	python setup.py sdist

dist/txtorcon-0.9.2-py27-none-any.whl:
	python setup.py bdist_wheel
dist/txtorcon-0.9.2-py27-none-any.whl.asc: dist/txtorcon-0.9.2-py27-none-any.whl
	gpg --verify dist/txtorcon-0.9.2-py27-none-any.whl.asc || gpg --no-version --detach-sign --armor --local-user meejah@meejah.ca dist/txtorcon-0.9.2-py27-none-any.whl

dist/txtorcon-0.9.2.tar.gz: sdist
dist/txtorcon-0.9.2.tar.gz.asc: dist/txtorcon-0.9.2.tar.gz
	gpg --verify dist/txtorcon-0.9.2.tar.gz.asc || gpg --no-version --detach-sign --armor --local-user meejah@meejah.ca dist/txtorcon-0.9.2.tar.gz

release:
	twine upload -r pypi -c "txtorcon v0.9.2 tarball" dist/txtorcon-0.9.2.tar.gz dist/txtorcon-0.9.2.tar.gz.asc
	twine upload -r pypi -c "txtorcon v0.9.2 wheel" dist/txtorcon-0.9.2-py27-none-any.whl dist/txtorcon-0.9.2-py27-none-any.whl.asc


venv:
	virtualenv --never-download --extra-search-dir=/usr/lib/python2.7/dist-packages/ venv
	@echo "created venv"
	@echo "see INSTALL for more information; to use:"
	@echo ". ./venv/bin/activate"
	@echo "pip install -r requirements.txt"
	@echo "pip install -r dev-requirements.txt"
	@echo "python examples/monitor.py"

html: docs/README.rst
	cd docs && make html
