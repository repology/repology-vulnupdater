PYTHON?=	python3
FLAKE8?=	flake8
MYPY?=		mypy

lint:: flake8 mypy test

flake8:
	${FLAKE8} repology-vulnupdater.py vulnupdater

mypy:
	${MYPY} ${MYPY_ARGS} repology-vulnupdater.py

test::
	${PYTHON} -m unittest discover
