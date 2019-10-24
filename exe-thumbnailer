#!/usr/bin/env python3
"""
Linux (freedesktop.org) thumbnailer for Windows PE files (.exe/.dll)

This takes in one argument: input file (%u), input URI (%i)
"""
import icoextract
import argparse
import hashlib
import pathlib
import traceback
import sys
import os

from gi.repository import GLib

from PIL import Image

def main(inputfile, uri):
    print("Got args:", sys.argv)
    thumb_hash = hashlib.md5(uri.encode('utf-8')).hexdigest().lower()
    basedir = pathlib.Path(GLib.get_user_cache_dir()) / "thumbnails"

    im = None

    extractor = icoextract.IconExtractor(inputfile)
    data = extractor.get_icon()

    im = Image.open(data)  # Open up the .ico from memory
    # Write a large icon if available
    if (256, 256) in im.info['sizes']:
        outdir = basedir / "large"
        os.makedirs(outdir, mode=0o700, exist_ok=True)
        outfile = outdir / (thumb_hash + '.png')
        print("Writing large size thumbnail to", outfile)
        im.save(outfile)

        # But also write a normal size icon in all cases - downscale to 128x128 per
        # https://specifications.freedesktop.org/thumbnail-spec/thumbnail-spec-latest.html
        # "Normal: The default place for storing thumbnails. The image size must not exceed 128x128 pixel."
        # Only some file managers (e.g. Caja) will show a thumbnail if only the large one exists?
        im.resize((128, 128))

    outdir = basedir / "normal"
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    outfile = outdir / (thumb_hash + '.png')
    print("Writing normal size thumbnail to", outfile)
    im.save(outfile)   # Convert it to a PNG

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inputfile", help="input file name")
    parser.add_argument("uri", help="input URI")
    args = parser.parse_args()

    main(args.inputfile, args.uri)
