# Tests for icoextract

## Basic tests

To compile these tests you need MinGW (x86_64 + i686) and imagemagick. On Debian/Ubuntu this is `apt install gcc-mingw-w64 imagemagick`.

```bash
make
python3 -m unittest discover .
```

## Win16 tests

To compile the binaries for `test_win16.py` you need the OpenWatcom C compiler (wcl, wrc).
This target is not enabled by default as OpenWatcom is not available in most distros. If Docker is installed and wcl/wrc
are not, the Makefile will try to build the Win16 test files with a public OpenWatcom Docker image instead.

```
bash
make win16
python3 -m unittest discover .
```

## 3rd Party Credits

The `testapp.png` icon file is sourced from the public domain [Tango icon theme](http://tango-project.org/) (`internet-web-browser.svg`).
