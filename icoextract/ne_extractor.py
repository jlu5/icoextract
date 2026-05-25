#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

import logging

try:
    import nefile
except ImportError:
    nefile = None

from .base_extractor import BaseIconExtractor
from .exceptions import (
    IconNotFoundError,
    NoIconsAvailableError
)
from .types import (
    ExtractedGroupIcon,
    GroupIconDirEntry,
    GroupIconWithIconOffsets,
    ResourceID,
)

logger = logging.getLogger("icoextract")

class NEIconExtractor(BaseIconExtractor):
    def __init__(self, filename=None, data=None):
        """
        Loads an Win16 New Executable from the given `filename` or `data` (raw buffer).
        If both `filename` and `data` are given, `filename` takes precedence.

        If the executable has contains no icons, this will raise `NoIconsAvailableError`.
        """
        if nefile is None:
            raise ImportError("nefile module must be installed to extract NE programs")
        self._ne = nefile.NE(filename, data)

        if not self._ne.resource_table:
            raise NoIconsAvailableError("Executable does not have any resources")
        if not (group_icon_resources := self._ne.resource_table.resources.get(
                nefile.resource_table.ResourceType.RT_GROUP_ICON)):
            raise NoIconsAvailableError("Executable does not have any group icons")

        self._group_icon_resources = group_icon_resources

    @staticmethod
    def _convert_nefile_icon_dir_entry(nefile_icon_dir_entry) -> GroupIconDirEntry:
        assert nefile is not None
        assert isinstance(nefile_icon_dir_entry, nefile.resources.icon.IconDirectoryEntry)
        return GroupIconDirEntry(
            Width=nefile_icon_dir_entry.width,
            Height=nefile_icon_dir_entry.height,
            ColorCount=nefile_icon_dir_entry.total_palette_colors,
            Planes=nefile_icon_dir_entry.color_planes,
            BitCount=nefile_icon_dir_entry.bits_per_pixel,
            BytesInRes=nefile_icon_dir_entry.icon_size_in_bytes,
            ID=nefile_icon_dir_entry.icon_resource_id,
        )

    def list_group_icons(self) -> list[tuple[ResourceID, GroupIconWithIconOffsets]]:
        assert nefile is not None
        result = []
        resources_offset = self._ne.resource_table.resource_table_start_offset
        icon_rtt = self._ne.resource_table.resource_type_tables[
            nefile.resource_table.ResourceType.RT_ICON
        ]
        icon_resource_declarations = {
            rdecl.id: rdecl for rdecl in icon_rtt.resource_declarations
        }
        for resource_id, nefile_group_icon in self._group_icon_resources.items():
            if isinstance(resource_id, str):
                resource_id_wrapper = ResourceID(raw_id=None, name=resource_id)
            else:
                resource_id_wrapper = ResourceID(resource_id)

            icon_infos = []
            for nefile_icon_dir_entry in nefile_group_icon.icon_directory.directory_entries:
                grp_icon_dir_entry = self._convert_nefile_icon_dir_entry(nefile_icon_dir_entry)
                icon_rdecl = icon_resource_declarations[grp_icon_dir_entry.ID]
                offset = icon_rdecl.data_start_offset
                file_offset = offset + resources_offset
                icon_infos.append((grp_icon_dir_entry, offset, file_offset))
            result.append((resource_id_wrapper, icon_infos))
        return result

    def _extract_icon(self, index: int = 0, resource_id: int | str | None = None) -> ExtractedGroupIcon:
        if resource_id is not None:
            try:
                nefile_group_icon = self._group_icon_resources[resource_id]
            except KeyError:
                raise IconNotFoundError(f"No icon exists with resource ID {resource_id!r}") from None
        else:
            icons_by_index = list(self._group_icon_resources.values())
            try:
                nefile_group_icon = icons_by_index[index]
            except IndexError:
                raise IconNotFoundError(f"No icon exists at index {index}") from None

        results = []
        for nefile_icon_dir_entry in nefile_group_icon.icon_directory.directory_entries:
            resource_id = nefile_icon_dir_entry.icon_resource_id
            grp_icon_dir_entry = self._convert_nefile_icon_dir_entry(nefile_icon_dir_entry)
            icondata = nefile_group_icon.icons[resource_id].data
            results.append((grp_icon_dir_entry, icondata))
        return results
