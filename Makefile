ENV = $(CURDIR)/env
BLACK = $(ENV)/bin/black
PYTHON3 = $(ENV)/bin/python3
FLAKE8 = $(ENV)/bin/flake8
PIP = $(PYTHON3) -m pip

test: $(ENV)
	$(PYTHON3) -m unittest tests

lint: $(ENV)
	$(MAKE) flake8
	$(BLACK) --check -l79 -t py38 *.py surl/*.py

$(ENV):
	virtualenv $(ENV) --python=python3
	${PIP} install -r requirements-dev.txt
	@touch $@

.PHONY: flake8
flake8: $(ENV)
	$(FLAKE8) *.py surl/*.py

black: $(ENV)
	$(BLACK) -l79 -t py38 *.py surl/*.py


