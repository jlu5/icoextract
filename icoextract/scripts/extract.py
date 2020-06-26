#!/usr/bin/env python3
"""
Windows PE EXE icon extractor.
"""
import argparse
import logging

from icoextract import IconExtractor, logger, __version__

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-V", "--version", action='version', version=f'icoextract {__version__}')
    parser.add_argument("-n", "--num", type=int, help="index of icon to extract", default=0)
    parser.add_argument("-v", "--verbose", action="store_true", help="enables debug logging")
    parser.add_argument("input", help="input filename")
    parser.add_argument("output", help="output filename")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    extractor = IconExtractor(args.input)
    extractor.export_icon(args.output, num=args.num)
