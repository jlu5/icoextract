For help on icoextract's frontend scripts, see `icoextract --help` and `icolist --help`.

## Using icoextract as a library

```python
from icoextract import IconExtractor, IconExtractorError

try:
    extractor = IconExtractor('/path/to/your.exe')

    # Export the first group icon to a .ico file
    extractor.export_icon('/path/to/your.ico', num=0)

    # Or save the .ico to a buffer, to pass it into another library
    data = extractor.get_icon(num=0)

    from PIL import Image
    im = Image.open(data)
    # ... manipulate a copy of the icon directly

except IconExtractorError:
    # No icons available, or the resource is malformed
    pass

```
