#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

# See https://devblogs.microsoft.com/oldnewthing/20120720-00/?p=7083
# for a reference on these structures

import ctypes

BYTE = ctypes.c_uint8
WORD = ctypes.c_uint16
DWORD = ctypes.c_uint32

class GroupIconDirEntry(ctypes.LittleEndianStructure):
    _pack_ = 1  # Ensures tight packing (no padding)
    _fields_ = [
        ("Width", BYTE),
        ("Height", BYTE),
        ("ColorCount", BYTE),
        ("Reserved", BYTE),
        ("Planes", WORD),
        ("BitCount", WORD),
        ("BytesInRes", DWORD),
        ("ID", WORD),
    ]

class GroupIconDir(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("Reserved", WORD),
        ("Type", WORD),
        ("Count", WORD),
    ]

ExtractedGroupIcon = list[tuple[GroupIconDirEntry, bytes]]
