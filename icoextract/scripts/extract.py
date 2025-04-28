#!/usr/bin/env python3
"""
Windows PE EXE icon extractor.
"""
import argparse
import logging
import os.path

from icoextract import IconExtractor, logger, __version__

_WRONG_EXTENSIONS_HINT = {'.jpg', '.jpeg', '.png'}
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-V", "--version", action='version', version=f'icoextract {__version__}')
    parser.add_argument("-n", "--num", type=int, help="index of icon to extract", default=0)
    parser.add_argument("-i", "--id", type=int, help="resource ID of icon to extract", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="enables debug logging")
    parser.add_argument("input", help="input filename (.exe/.dll/.mun)")
    parser.add_argument("output", help="output filename (.ico)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    extractor = IconExtractor(args.input)
    extractor.export_icon(args.output, num=args.num, resource_id=args.id)
    file_ext = os.path.splitext(args.output)[1].lower()
    if file_ext in _WRONG_EXTENSIONS_HINT:
        logger.warning('This tool outputs .ico files, not %s. The resulting file will have the wrong file extension.',
                       file_ext)
