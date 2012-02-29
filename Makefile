.PHONY: test html counts coverage sdist
.DEFAULT: test

test:
	trial --reporter=text txtorcon

coverage:
	trial --reporter=bwverbose --coverage txtorcon
	python scripts/coverage.py

counts:
	ohcount -s txtorcon/__init__.py txtorcon/torcontrolprotocol.py txtorcon/router.py txtorcon/torstate.py txtorcon/torconfig.py txtorcon/addrmap.py txtorcon/stream.py txtorcon/spaghetti.py txtorcon/circuit.py

sdist:
	python setup.py sdist

html: README index.md
	-mkdir html
	python scripts/md-render.py index.md > html/index.html
	python scripts/md-render.py README > html/README.html
