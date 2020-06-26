# icoextract

icoextract is an icon extractor for Windows PE files (.exe/.dll), written in Python. It also includes a thumbnailer script (exe-thumbnailer) for Linux desktops.

This project is inspired by [extract-icon-py](https://github.com/firodj/extract-icon-py), [icoutils](https://www.nongnu.org/icoutils/), and others.

## Installation

Global install:

```
pip3 install -r requirements.txt
python3 setup.py install
mkdir -p /usr/local/share/thumbnailers/
cp exe-thumbnailer.thumbnailer /usr/local/share/thumbnailers/
```

Local install:

```
pip3 install -r requirements.txt
python3 setup.py install --user
mkdir -p ~/.local/share/thumbnailers/
cp exe-thumbnailer.thumbnailer ~/.local/share/thumbnailers/
```

## Usage

```cmd
python extract.py <some-program.exe> <destination-icon.ico> 
```

## Goals

This project aims to be:

- Lightweight
- Portable (cross-platform)
- Fast on large files
