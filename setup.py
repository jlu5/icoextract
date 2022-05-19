#!/usr/bin/env python3

from setuptools import setup, find_packages

with open('icoextract/version.py') as f:
    exec(f.read())

setup(
    name="icoextract",
    description="Windows PE EXE icon extractor",
    version=__version__,
    url="https://github.com/jlu5/icoextract",

    author="James Lu",
    author_email="james@overdrivenetworks.com",

    license="MIT/Expat",
    classifiers=[
        # https://pypi.org/classifiers/
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],

    packages=find_packages(exclude=['tests']),
    install_requires=['pefile'],
    extras_require={
        "thumbnailer": ["Pillow"]
    },

    # Executable scripts
    entry_points={
        'console_scripts': [
            'icoextract = icoextract.scripts.extract:main',
            'icolist = icoextract.scripts.icolist:main',
            'exe-thumbnailer = icoextract.scripts.thumbnailer:main [thumbnailer]',
        ],
    },
)
