#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>
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
        resource_id, grp_icon_dir_entries = entry
        print(f"Group Icon Index: {idx}    ", end='')

        print(f"ID: {resource_id}", end='')
        if resource_id.raw_id:
            print(f"({hex(resource_id.raw_id)})", end='')
        print("    ", end='')

        print(f"Count: {len(grp_icon_dir_entries)}")
        for (grp_icon_dir_entry, resource_offset, file_offset) in grp_icon_dir_entries:
            print(f"    Icon ID: {grp_icon_dir_entry.ID}"
                  # Width and Height are u8 values where 0 means 256
                  f"    Width: {grp_icon_dir_entry.Width or 256}"
                  f"    Height: {grp_icon_dir_entry.Height or 256}"
                  f"    Resource Offset: {hex(resource_offset)}"
                  f"    File Offset: {hex(file_offset)}"
                  f"    Size: {grp_icon_dir_entry.BytesInRes}")
