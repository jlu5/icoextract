# icoextract

**icoextract** is an icon extractor for Windows PE files (.exe/.dll), written in Python. It also includes a thumbnailer script (`exe-thumbnailer`) for Linux desktops.

This project is inspired by [extract-icon-py](https://github.com/firodj/extract-icon-py), [icoutils](https://www.nongnu.org/icoutils/), and others.

icoextract aims to be:

- Lightweight
- Portable (cross-platform)
- Fast on large files

## Installation

You can install the project via pip: `pip3 install icoextract`

On Linux, you can optionally install the thumbnailer by copying [`exe-thumbnailer.thumbnailer`](/exe-thumbnailer.thumbnailer) into `/usr/local/share/thumbnailers/`


## Usage

icoextract ships `icoextract` and `icolist` scripts to extract and list icon resources in an executable:

```
usage: icoextract [-h] [-V] [-n NUM] [-v] input output

Windows PE EXE icon extractor.

positional arguments:
  input              input filename
  output             output filename

optional arguments:
  -h, --help         show this help message and exit
  -V, --version      show program's version number and exit
  -n NUM, --num NUM  index of icon to extract
  -v, --verbose      enables debug logging
```

```
usage: icolist [-h] [-V] [-v] input

Lists group icons present in a program.

positional arguments:
  input          input filename

optional arguments:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit
  -v, --verbose  enables debug logging
```
