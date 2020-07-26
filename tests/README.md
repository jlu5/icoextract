## Tests for icoextract

To compile these tests you need MinGW and imagemagick. On Debian/Ubuntu this is `apt install gcc-mingw-w64 imagemagick`.

```bash
make
python3 test_icoextract.py
```

The icon file (`testapp.png`) is sourced from the public domain [Tango icon theme](http://tango-project.org/) (`internet-web-browser.svg`).
