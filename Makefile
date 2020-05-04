FLAKE8?=	flake8
MYPY?=		mypy
BLACK?=		black

FLAKE8_ARGS+=	--ignore=D10,E501
FLAKE8_ARGS+=	--max-line-length 88  # same as black
MYPY_ARGS+=	--strict --ignore-missing-imports
BLACK_ARGS=	--skip-string-normalization

lint:: flake8 mypy test

flake8:
	${FLAKE8} ${FLAKE8_ARGS} repology-vulnupdater.py vulnupdater

mypy:
	${MYPY} ${MYPY_ARGS} repology-vulnupdater.py

test::
	python3 -m unittest discover
