#!/usr/bin/env python3
"""
Linux (freedesktop.org) thumbnailer for Windows PE files (.exe/.dll)
"""
import argparse
import logging
import sys

from PIL import Image

from icoextract import IconExtractor, logger, __version__

def generate_thumbnail(inputfile, outfile, size=256, force_resize=False):
    """
    Generates a thumbnail for an .exe file.

    inputfile: the input file path (%i)
    outfile: output filename (%o)
    size: determines the thumbnail output size (%s)
    """
    try:
        extractor = IconExtractor(inputfile)
    except RuntimeError:
        logger.debug("Failed to extract icon for %s:", inputfile, exc_info=True)
        sys.exit(1)
    data = extractor.get_icon()

    im = Image.open(data)  # Open up the .ico from memory
    if force_resize:
        logger.debug("Force resizing icon to %dx%d", size, size)
        im = im.resize((size, size))
    else:
        if size > 256:
            logger.warning('Icon sizes over 256x256 are not supported')
            size = 256
        elif size not in (128, 256):
            logger.warning('Unsupported size %d, falling back to 128x128', size)
            size = 128

        # Note: 256x256 is the largest size supported by the .ico format
        if size == 256:
            # A large size thumbnail was requested. No downwards resizing is needed, so export any icon as is
            logger.debug("Writing large size thumbnail for %s to %s", inputfile, outfile)
            im.save(outfile, "PNG")
            return

        # If large size thumbnail wasn't requested but one is available, pick an 128x128 icon if available;
        # otherwise scale down from 256x256 to 128x128. 128x128 is the largest resolution allowed for
        # "normal" size thumbnails.
        if (128, 128) in im.info['sizes']:
            logger.debug("Using native 128x128 icon")
            im.size = (128, 128)
        elif im.size > (128, 128):
            logger.debug("Downsizing icon to 128x128")
            im = im.resize((128, 128))
        logger.debug("Writing normal size thumbnail for %s to %s", inputfile, outfile)

    im.save(outfile, "PNG")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-V", "--version", action='version', version=f'exe-thumbnailer, part of icoextract {__version__}')
    parser.add_argument("-s", "--size", type=int, help="size of desired thumbnail", default=256)
    parser.add_argument("-v", "--verbose", action="store_true", help="enables debug logging")
    parser.add_argument("-f", "--force-resize", action="store_true", help="force resize thumbnail to the specified size")
    parser.add_argument("inputfile", help="input file name (.exe/.dll/.mun)")
    parser.add_argument("outfile", help="output file name (.png)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    generate_thumbnail(args.inputfile, args.outfile, size=args.size, force_resize=args.force_resize)
