#!/usr/bin/env python3
"""
Linux (freedesktop.org) thumbnailer for Windows PE files (.exe/.dll)
"""
import argparse
import logging
import sys

from PIL import Image

from icoextract import IconExtractor, logger, __version__

def generate_thumbnail(inputfile, outfile, large_size=True):
    """
    Generates a thumbnail for an .exe file.

    inputfile: the input file path (%i)
    outfile: output filename (%o)
    large_size: determines whether to write a large size (256x256) thumbnail (%s)
    """
    try:
        extractor = IconExtractor(inputfile)
    except RuntimeError:
        logger.debug("Failed to extract icon for %s:", inputfile, exc_info=True)
        sys.exit(1)
    data = extractor.get_icon()

    im = Image.open(data)  # Open up the .ico from memory
    if (256, 256) in im.info['sizes']:
        if large_size:
            # A large size thumbnail was requested
            logger.debug("Writing large size thumbnail for %s to %s", inputfile, outfile)
            im.save(outfile, "PNG")
            return

        # If large size thumbnail wasn't requested but one is available,
        # scale it down to 128x128. This is the largest resolution allowed
        # for "normal" size thumbnails.
        im.resize((128, 128))

    logger.debug("Writing normal size thumbnail for %s to %s", inputfile, outfile)
    im.save(outfile, "PNG")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-V", "--version", action='version', version=f'exe-thumbnailer, part of icoextract {__version__}')
    parser.add_argument("-s", "--size", type=int, help="size of desired thumbnail", default=256)
    parser.add_argument("-v", "--verbose", action="store_true", help="enables debug logging")
    parser.add_argument("inputfile", help="input file name")
    parser.add_argument("outfile", help="output file name", nargs='?')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    large_size = (args.size >= 256)
    generate_thumbnail(args.inputfile, args.outfile, large_size)
