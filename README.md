# icoextract

A pure Python icon extractor for Windows PE files (.exe/.dll). Inspired by [firodj/extract-icon-py](https://github.com/firodj/extract-icon-py), [icoutils](https://www.nongnu.org/icoutils/), and others.

## Goals

This project aims to be:

- Lightweight
- Portable (cross-platform)
- Fast on large files

## Dependencies

icoextract uses [pefile](https://github.com/erocarrera/pefile) to do much of the heavy lifting.