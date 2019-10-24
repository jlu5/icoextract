#!/usr/bin/env python3

import sys
from setuptools import setup

if sys.version_info < (3, 6):
    raise RuntimeError("icoextract requires Python 3.6 or higher.")

with open('VERSION', encoding='utf-8') as f:
    VERSION = f.read().strip()

setup(
    name="icoextract",
    description="Windows PE EXE icon extractor",
    version=VERSION,

    url="https://github.com/jlu5/icoextract",

    author="James Lu",
    author_email="james@overdrivenetworks.com",

    license="MIT/Expat",

    packages=["icoextract"],
    package_dir={"icoextract": "src"},

    # Executable scripts
    scripts=["icoextract", "icolist", "exe-thumbnailer"],
)
