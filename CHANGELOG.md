# Changelog

## icoextract 0.1.3 (2022-06-12)

- Fix thumbnail resizing; use native 128x128 icons when available (GH-7)
- Clarify installation steps for thumbnailer
- setup.py: exclude `tests` from installed packages (GH-9)

## icoextract 0.1.2 (2020-12-22)

- Declare Pillow as an optional dependency (for icoextract-thumbnailer)
- Fix autodiscovery for tests

## icoextract 0.1.1 (2020-07-01)

- Refactor scripts to use setuptools entrypoints (adds Windows support)
- Raise an error when seeing invalid icon definitions

## icoextract 0.1.0 (2019-11-22)

- Initial release
