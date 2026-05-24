#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2015-2016 Fadhil Mandaga
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

import ctypes
import logging
import os
import pathlib
import platform

import pefile

from .base_extractor import BaseIconExtractor
from .exceptions import (
    IconNotFoundError,
    InvalidIconDefinitionError,
    NoIconsAvailableError
)
from .types import (
    ExtractedGroupIcon,
    GroupIconDir,
    GroupIconDirEntry,
    GroupIconWithIconOffsets,
    ResourceID,
)

logger = logging.getLogger("icoextract")

class PEIconExtractor(BaseIconExtractor):
    def __init__(self, filename=None, data=None):
        """
        Loads an Win32/Win64 Portable Executable from the given `filename` or `data` (raw buffer).
        If both `filename` and `data` are given, `filename` takes precedence.

        If the executable has contains no icons, this will raise `NoIconsAvailableError`.
        """
        # Use fast loading and explicitly load the RESOURCE directory entry. This saves a LOT of time
        # on larger files
        self._pe = pefile.PE(name=filename, data=data, fast_load=True)
        self._pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])

        if not hasattr(self._pe, 'DIRECTORY_ENTRY_RESOURCE'):
            raise NoIconsAvailableError("File has no resources")

        # Reverse the list of entries before making the mapping so that earlier values take precedence
        # When an executable includes multiple icon resources, we should use only the first one.
        # pylint: disable=no-member
        resources = {rsrc.id: rsrc for rsrc in reversed(self._pe.DIRECTORY_ENTRY_RESOURCE.entries)}

        self._groupiconres = resources.get(pefile.RESOURCE_TYPE["RT_GROUP_ICON"])
        if not self._groupiconres:
            if filename and platform.system() == "Windows":
                self._print_windows_usage_hint(filename)
            raise NoIconsAvailableError("File has no group icon resources")
        self._rticonres = resources.get(pefile.RESOURCE_TYPE["RT_ICON"])

        self._group_icons = self._groupiconres.directory.entries
        self._group_icons_by_id: dict[int | str, pefile.ResourceDirEntryData] = {}
        for entry in self._group_icons:
            self._group_icons_by_id[entry.struct.Name] = entry
            # For resources with a string name, track them by both the string and the underlying
            # numerical index
            if entry.name:
                self._group_icons_by_id[str(entry.name)] = entry

        self._icons = {icon_entry_list.id: icon_entry_list.directory.entries[0]  # Select first language
                       for icon_entry_list in self._rticonres.directory.entries}

    def list_group_icons(self) -> list[tuple[ResourceID, GroupIconWithIconOffsets]]:
        results = []
        for entry in self._group_icons:
            resource_id = ResourceID(
                raw_id=entry.struct.Name,
                name=str(entry.name) if entry.name else None
            )
            grp_icon_resource = self._group_icons_by_id[entry.struct.Name]
            grp_icon_data_full = self._extract_from_pefile(grp_icon_resource, skip_data=True)
            # Return only the metadata and offsets
            grp_icon_data = [
                (grp_icon_dir_entry, resource_offset, file_offset)
                for (grp_icon_dir_entry, _, resource_offset, file_offset)
                in grp_icon_data_full
            ]
            results.append((resource_id, grp_icon_data))
        return results

    def _extract_from_pefile(
        self,
        resource_dir_entry_data: pefile.ResourceDirEntryData,
        skip_data: bool = False,
    ) -> list[tuple[GroupIconDirEntry, bytes, int, int]]:
        """
        Returns the specified group icon in the binary.

        Result is a list of (group icon dir entry, icon data) tuples.
        """
        icon_lang = None
        if resource_dir_entry_data.struct.DataIsDirectory:
            # Select the first language from subfolders as needed.
            resource_dir_entry_data = resource_dir_entry_data.directory.entries[0]
            icon_lang = resource_dir_entry_data.struct.Name
            logger.debug("Picking first language %s", icon_lang)

        # Read the data pointed to by the group icon directory (GRPICONDIR) struct.
        rva = resource_dir_entry_data.data.struct.OffsetToData
        grp_icon_data = self._pe.get_data(rva, resource_dir_entry_data.data.struct.Size)

        grp_icon_dir = GroupIconDir.from_buffer_copy(grp_icon_data)
        logger.debug("Group icon has %d images: %s",
                     grp_icon_dir.Count, grp_icon_dir)

        # pylint: disable=no-member
        if grp_icon_dir.Reserved:
            # pylint: disable=no-member
            raise InvalidIconDefinitionError("Invalid group icon definition (got Reserved=%s instead of 0)"
                % hex(grp_icon_dir.Reserved))

        # For each group icon entry (GRPICONDIRENTRY) that immediately follows, read the struct and look up the
        # corresponding icon image
        extracted_grp_icons = []
        icon_offset = ctypes.sizeof(grp_icon_dir)
        for grp_icon_index in range(grp_icon_dir.Count):
            grp_icon_dir_entry = GroupIconDirEntry.from_buffer_copy(grp_icon_data, icon_offset)
            icon_offset += ctypes.sizeof(grp_icon_dir_entry)
            logger.debug("Got group icon entry %d: %s", grp_icon_index, grp_icon_dir_entry)

            icon_entry = self._icons[grp_icon_dir_entry.ID]
            logger.debug("Got icon data for ID %d: %s", grp_icon_dir_entry.ID, icon_entry.data.struct)

            icon_res_offset = icon_entry.data.struct.OffsetToData
            icon_file_offset = self._pe.get_offset_from_rva(icon_res_offset)
            icon_data = b''
            if not skip_data:
                icon_data = self._pe.get_data(icon_res_offset, icon_entry.data.struct.Size)
            extracted_grp_icons.append((grp_icon_dir_entry, icon_data, icon_res_offset, icon_file_offset))
        return extracted_grp_icons

    def _extract_icon(self, index: int = 0, resource_id: int | str | None = None) -> ExtractedGroupIcon:
        if resource_id is not None:
            try:
                resource_dir_entry_data = self._group_icons_by_id[resource_id]
            except KeyError:
                raise IconNotFoundError(f"No icon exists with resource ID {resource_id!r}") from None
        else:
            try:
                resource_dir_entry_data = self._group_icons[index]
            except IndexError:
                raise IconNotFoundError(f"No icon exists at index {index}") from None

        # Return only the GroupIconDirEntry metadata and icon bytes
        return [
            (grp_icon_dir_entry, icon_data)
            for (grp_icon_dir_entry, icon_data, _, _)
            in self._extract_from_pefile(resource_dir_entry_data)
        ]

    @staticmethod
    def _print_windows_usage_hint(filename):
        path = pathlib.Path(filename)
        systemroot = pathlib.Path(os.getenv('SYSTEMROOT'))
        if path.is_relative_to(systemroot / 'System32') or \
                path.is_relative_to(systemroot / 'SysWOW64'):
            mun_path = pathlib.Path(systemroot / 'SystemResources' / (path.name + '.mun'))
            if mun_path.is_file():
                logger.warning(
                    'System DLL files in Windows 10 1903+ no longer contain icons. '
                    'Try extracting from %s instead.', mun_path)
