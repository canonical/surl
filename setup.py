#!/usr/bin/env python3

import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name='surl',
    version='0.7.2',
    author='Celso Providelo',
    author_email='celso.providelo@canonical.com',
    url="https://github.com/cprov/surl",
    license='GPL-3.0',
    description='Ubuntu Store API thin wrapper.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    install_requires=[
        "requests",
        "pymacaroons",
        "tabulate",
        "iso8601",
    ],
    test_suite='tests',
    setup_requires=[
        "flake8"
    ],
    scripts=[
        'surl_cli.py',
        'surl_metrics.py',
        'surl_storeops.py',
        'surl_month_in_snaps.py',
    ],
    packages=setuptools.find_packages(),
)
