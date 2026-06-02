#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2015-2016 Fadhil Mandaga
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>
"""
Windows Portable Executable (PE) icon extractor.

.. include:: ../LIB-USAGE.md
"""

from contextlib import ExitStack
import enum
import logging
import mmap

from .base_extractor import BaseIconExtractor
from .exceptions import (
    IconExtractorError,
    IconNotFoundError,
    NoIconsAvailableError,
    InvalidIconDefinitionError,
    UnknownExecutableError,
)
from .ne_extractor import NEIconExtractor
from .pe_extractor import PEIconExtractor

logger = logging.getLogger("icoextract")
logging.basicConfig()

try:
    from .version import __version__
except ImportError:
    __version__ = 'unknown'
    logger.info('icoextract: failed to read program version')

__all__ = [
    'IconExtractor',
    'IconExtractorError',
    'IconNotFoundError',
    'NoIconsAvailableError',
    'InvalidIconDefinitionError',
    'UnknownExecutableError',
    'ExecutableType',
]

class ExecutableType(enum.Enum):
    """Enum for supported executable formats."""
    AUTO = 0
    PE = 1
    NE = 2

def detect_executable_type(buf: bytearray | mmap.mmap) -> ExecutableType:
    if buf[:2] != b'MZ':
        raise UnknownExecutableError("Unknown executable type (no MZ header)")

    # Get the offset to the real header (located at 0x3C)
    e_lfanew = int.from_bytes(buf[0x3C:0x40], byteorder='little')
    signature = buf[e_lfanew:e_lfanew+4]

    if signature.startswith(b'PE\x00\x00'):
        return ExecutableType.PE
    if signature.startswith(b'NE'):
        return ExecutableType.NE
    raise UnknownExecutableError("Unknown / unsupported executable type")

def IconExtractor(filename: str | None = None,
                  data: bytearray | mmap.mmap | None = None,
                  exe_type: ExecutableType = ExecutableType.AUTO) -> BaseIconExtractor:
    """IconExtractor factory function."""
    if filename is None and data is None:
        raise ValueError("filename and data cannot both be None")

    if exe_type == ExecutableType.AUTO:
        if data is not None:
            exe_type = detect_executable_type(data)
        else:
            assert filename
            with ExitStack() as stack:
                f = stack.enter_context(open(filename, 'rb'))
                mm = stack.enter_context(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ))
                exe_type = detect_executable_type(mm)
        logger.debug("Detected executable type as %s", exe_type)

    if exe_type == ExecutableType.PE:
        return PEIconExtractor(filename, data)
    if exe_type == ExecutableType.NE:
        return NEIconExtractor(filename, data)

    raise UnknownExecutableError("Unknown executable type")

__pdoc__ = {
    'scripts': False,
    'version': False,
}
