#!/usr/bin/env python3
"""
Lists group icons present in a program.
"""
import argparse
import logging

from icoextract import IconExtractor, logger, __version__

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-V", "--version", action='version', version=f'icoextract {__version__}')
    parser.add_argument("-v", "--verbose", action="store_true", help="enables debug logging")
    parser.add_argument("input", help="input filename")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    extractor = IconExtractor(args.input)
    for idx, entry in enumerate(extractor.list_group_icons()):
        eid, offset = entry
        print(f"Index: {idx}    "
              f"ID: {eid}({hex(eid)})    "
              f"Offset: {hex(offset)}")
