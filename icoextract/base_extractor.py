#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>
from __future__ import annotations

import abc
import io
import struct

from .types import ExtractedGroupIcon, ResourceID

class BaseIconExtractor(abc.ABC):
    """Base icon extractor class containing frontend and .ico writing logic."""

    @abc.abstractmethod
    def _extract_icon(self, index: int = 0, resource_id: int | str | None = None) -> ExtractedGroupIcon:
        """Extract an icon by its index or resource ID."""

    @abc.abstractmethod
    def list_group_icons(self) -> list[tuple[ResourceID, int]]:
        """
        Returns all group icon entries as a list of (resource ID, offset) tuples.
        """

    def _write_ico(self, fd, icons: ExtractedGroupIcon):
        """Writes ICO data to a file descriptor."""
        fd.write(b"\x00\x00") # 2 reserved bytes
        fd.write(struct.pack("<H", 1)) # 0x1 (little endian) specifying that this is an .ICO image
        fd.write(struct.pack("<H", len(icons)))  # number of images

        dataoffset = 6 + (len(icons) * 16)
        # First pass: write the icon dir entries
        for datapair in icons:
            group_icon, icon_data = datapair
            # Elements in ICONDIRENTRY and GRPICONDIRENTRY are all the same
            # except the last value, which is a 2 byte ID in GRPICONDIRENTRY and
            # the 4 byte offset from the beginning of the file in ICONDIRENTRY.
            fd.write(bytes(group_icon)[:12])
            fd.write(struct.pack("<I", dataoffset))
            dataoffset += len(icon_data)  # Increase offset for next image

        # Second pass: write the icon data
        for datapair in icons:
            group_icon, icon_data = datapair
            fd.write(icon_data)

    def export_icon(self, filename: str, num: int = 0, resource_id: int | str | None = None) -> None:
        """
        Exports ICO data for the requested group icon to `filename`.

        Icons can be selected by index (`num`) or resource ID. By default, the first icon in the binary is exported.
        """
        group_icon = self._extract_icon(index=num, resource_id=resource_id)
        with open(filename, 'wb') as f:
            self._write_ico(f, group_icon)

    def get_icon(self, num: int = 0, resource_id: int | str | None = None) -> io.BytesIO:
        """
        Exports ICO data for the requested group icon as a `io.BytesIO` instance.

        Icons can be selected by index (`num`) or resource ID. By default, the first icon in the binary is exported.
        """
        group_icon = self._extract_icon(index=num, resource_id=resource_id)
        f = io.BytesIO()
        self._write_ico(f, group_icon)
        return f
