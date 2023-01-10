#!/usr/bin/env python3

import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="surl",
    version="1.0.3",
    author="Snap Store Team",
    author_email="daniel.manrique@canonical.com",
    url="https://github.com/canonical/surl",
    license="GPL-3.0",
    description="Ubuntu Store API thin wrapper.",
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
    test_suite="tests",
    setup_requires=["flake8"],
    scripts=[
        "surl_cli.py",
        "surl_metrics.py",
        "surl_storeops.py",
        "surl_month_in_snaps.py",
    ],
    packages=setuptools.find_packages(),
)
