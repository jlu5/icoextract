#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

# See https://devblogs.microsoft.com/oldnewthing/20120720-00/?p=7083
# for a reference on these structures

import ctypes

BYTE = ctypes.c_uint8
WORD = ctypes.c_uint16
DWORD = ctypes.c_uint32

class ResourceID(int):
    """Resource ID wrapper.

    For resources with a string ID, str() will return its string value
    (e.g. "IDI_MAIN_ICON") and int() will return its underlying numeric ID.

    Numerical icon resource IDs can be accessed via int(), and str() will return
    the number casted to a string.
    """
    def __new__(cls, raw_id: int, name: str | None = None):
        return super().__new__(cls, raw_id)

    def __init__(self, raw_id: int, name: str | None = None):
        self.raw_id = raw_id
        self.name = name

    def __str__(self):
        return self.name or str(self.raw_id)

    def __repr__(self):
        if self.name:
            return f'{self.__class__.__name__}({self.name!r})'
        return f'{self.__class__.__name__}({self.raw_id})'

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
