#!/usr/bin/env python3

from setuptools import setup


def read_requirements(filename):
    with open(filename, 'r') as f:
        return [line for line in f.readlines() if not line.startswith('-')]


setup(
    name='repology-vulnupdater',
    version='0.0.0',
    description='Vulnerability data updater for Repology project',
    author='Dmitry Marakasov',
    author_email='amdmi3@amdmi3.ru',
    url='https://repology.org/',
    license='GNU General Public License v3 or later (GPLv3+)',
    packages=[
        'vulnupdater',
    ],
    scripts=[
        'repology-vulnupdater.py',
    ],
    classifiers=[
        'Topic :: Security',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.8',
    ],
    python_requires='>=3.8',
    install_requires=read_requirements('requirements.txt')
)
