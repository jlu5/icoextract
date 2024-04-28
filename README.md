# icoextract

[![Build Status](https://drone.overdrivenetworks.com/api/badges/jlu5/icoextract/status.svg)](https://drone.overdrivenetworks.com/jlu5/icoextract)

**icoextract** is an icon extractor for Windows PE files (.exe/.dll/.mun), written in Python. It also includes a thumbnailer script (`exe-thumbnailer`) for Linux desktops.

This project is inspired by [extract-icon-py](https://github.com/firodj/extract-icon-py), [icoutils](https://www.nongnu.org/icoutils/), and others.

icoextract aims to be:

- Lightweight
- Portable (cross-platform)
- Fast on large files

## Installation

### Installing from source

You can install the project via pip: `pip3 install icoextract[thumbnailer]`

On Linux, you can activate the thumbnailer by copying [`exe-thumbnailer.thumbnailer`](/exe-thumbnailer.thumbnailer) into the thumbnailers directory:

- `/usr/local/share/thumbnailers/` if you installed `icoextract` globally
- `~/.local/share/thumbnailers` if you installed `icoextract` for your user only

The thumbnailer should work with any file manager that implements the [Freedesktop Thumbnails Standard](https://specifications.freedesktop.org/thumbnail-spec/thumbnail-spec-latest.html): this includes Nautilus, Caja, Nemo, Thunar (when Tumbler is installed), and PCManFM. KDE / Dolphin uses a different architecture and is *not* supported here.

### Distribution packages

You can install icoextract from any of these distribution repositories:

[![Packaging status](https://repology.org/badge/vertical-allrepos/icoextract.svg)](https://repology.org/project/icoextract/versions)

## Usage

icoextract ships `icoextract` and `icolist` scripts to extract and list icon resources inside a file.

**Note**: recent versions of Windows (Windows 10 1903+) have moved icons from system libraries (`shell32.dll`, etc.) into a new [`C:\Windows\SystemResources`](https://superuser.com/questions/1480268/) folder. icoextract can extract these `.mun` files natively, but the `.dll`s themselves no longer contain icons.

For API docs, see https://projects.jlu5.com/icoextract.html

```
usage: icoextract [-h] [-V] [-n NUM] [-v] input output

Windows PE EXE icon extractor.

positional arguments:
  input              input filename (.exe/.dll/.mun)
  output             output filename (.ico)

options:
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

options:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit
  -v, --verbose  enables debug logging
```
