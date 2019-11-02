# icoextract

A pure Python icon extractor for Windows PE files (.exe/.dll). Inspired by [extract-icon-py](https://github.com/firodj/extract-icon-py), [icoutils](https://www.nongnu.org/icoutils/), and others.

## Installation

Global install:

```
python3 setup.py install
mkdir -p /usr/local/share/thumbnailers/
cp exe-thumbnailer.thumbnailer /usr/local/share/thumbnailers/
```

Local install:

```
python3 setup.py install --user
mkdir -p ~/.local/share/thumbnailers/
cp exe-thumbnailer.thumbnailer ~/.local/share/thumbnailers/
```

## Goals

This project aims to be:

- Lightweight
- Portable (cross-platform)
- Fast on large files

## Dependencies

icoextract uses [pefile](https://github.com/erocarrera/pefile) to do much of the heavy lifting.
