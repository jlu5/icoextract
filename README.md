# icoextract

[![Build Status](https://woodpecker.overdrivenetworks.com/api/badges/5/status.svg)](https://woodpecker.overdrivenetworks.com/repos/5)
[![Packaging status](https://repology.org/badge/tiny-repos/icoextract.svg)](https://repology.org/project/icoextract/versions)

<!-- BEGIN API docs include -->

**icoextract** is an icon extractor library for Windows executables (.exe/.dll/.mun). It also includes a thumbnailer script (`exe-thumbnailer`) for Linux desktops.

This project is inspired by [extract-icon-py](https://github.com/firodj/extract-icon-py), [icoutils](https://www.nongnu.org/icoutils/), and others.

## Installation

### Dependencies

- Python 3.10+
- [pefile](https://github.com/erocarrera/pefile)
- [Pillow](https://pillow.readthedocs.io/en/stable/) - optional, for exe-thumbnailer
- [nefile](https://github.com/npjg/nefile) - optional, for Win16 / NE EXE support

### Installing from source

You can install the project via pip: `pip3 install icoextract[thumbnailer]`, or
the Git repo at https://github.com/jlu5/icoextract

On Linux, you can enable the thumbnailer by copying [`exe-thumbnailer.thumbnailer`](https://github.com/jlu5/icoextract/blob/master/exe-thumbnailer.thumbnailer) into the thumbnailers directory:

- `/usr/local/share/thumbnailers/` if you installed icoextract globally
- `~/.local/share/thumbnailers` if you installed icoextract for your user only

The thumbnailer should work with any file manager that implements the [Freedesktop Thumbnails Standard](https://specifications.freedesktop.org/thumbnail-spec/thumbnail-spec-latest.html): this includes Nautilus, Caja, Nemo, Thunar (when Tumbler is installed), and PCManFM. KDE / Dolphin uses a different architecture and is *not* supported here.

### Distribution packages

You can install icoextract from any of these distribution repositories:

[![Packaging status](https://repology.org/badge/vertical-allrepos/icoextract.svg?columns=5)](https://repology.org/project/icoextract/versions)


## Usage

**Note**: recent versions of Windows (Windows 10 1903+) have moved icons from system libraries (`shell32.dll`, etc.) into a new [`C:\Windows\SystemResources`](https://superuser.com/questions/1480268/) folder. icoextract can extract these `.mun` files natively, but the `.dll`s themselves no longer contain icons.

### icoextract CLI

icoextract ships **icoextract** and **icolist** scripts to extract and list icon resources inside a file.

```
usage: icoextract [-h] [-V] [-n NUM] [-i ID] [-v] input output

Windows executable icon extractor.

positional arguments:
  input          input filename (.exe/.dll/.mun)
  output         output filename (.ico)

options:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit
  -n, --num NUM  index of icon to extract
  -i, --id ID    resource ID of icon to extract
  -v, --verbose  enables debug logging
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

### Using icoextract as a Library

```python
from icoextract import IconExtractor, IconExtractorError

try:
    extractor = IconExtractor('/path/to/your.exe')

    # Export the first group icon to a .ico file
    extractor.export_icon('/path/to/your.ico', num=0)

    # Or read the .ico into a buffer, to pass it into other code
    data = extractor.get_icon(num=0)

    from PIL import Image
    im = Image.open(data)
    # ... manipulate a copy of the icon

    # In icoextract 0.2.0+, you can also extract icons by resource ID
    extractor.export_icon('/path/to/your.ico', resource_id=1234)

except IconExtractorError:
    # No icons available, or the icon resource is malformed
    pass

```

<!-- END API docs include -->

For full API docs, see https://projects.jlu5.com/icoextract.html
