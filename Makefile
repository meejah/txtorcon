.PHONY: test
.DEFAULT: test

test:
	trial --reporter=text txtorcon

coverage:
	trial --reporter=bwverbose --coverage txtorcon
	python coverage.py

counts:
	ohcount -s txtorcon/__init__.py txtorcon/torcontrolprotocol.py txtorcon/router.py txtorcon/torstate.py txtorcon/torconfig.py txtorcon/addrmap.py txtorcon/stream.py txtorcon/spaghetti.py txtorcon/circuit.py

sdist:
	python setup.py sdist

html: README index.md
	python md-render.py index.md > html/index.html
	python md-render.py README > html/README.html
