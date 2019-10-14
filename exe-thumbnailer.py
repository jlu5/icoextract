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
from PIL.IcoImagePlugin import IcoFile

def main(inputfile, uri):
    print("Got args:", sys.argv)
    thumb_hash = hashlib.md5(uri.encode('utf-8')).hexdigest().lower()
    basedir = pathlib.Path(GLib.get_user_cache_dir()) / "thumbnails"

    im = None
    try:
        extractor = icoextract.IconExtractor(inputfile)
        data = extractor.get_icon()

        im = Image.open(data)  # Open up the .ico from memory
        if (256, 256) in im.info['sizes']:
            outdir = basedir / "large"
        else:
            outdir = basedir / "normal"
    except:
        traceback.print_exc()
        outdir = basedir / "fail"

    os.makedirs(outdir, mode=0o700, exist_ok=True)
    outfile = outdir / (thumb_hash + '.png')
    print("Writing thumbnail to", outfile)
    if im:
        im.save(outfile)   # Convert it to a PNG

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inputfile", help="input file name")
    parser.add_argument("uri", help="input URI")
    args = parser.parse_args()

    main(args.inputfile, args.uri)