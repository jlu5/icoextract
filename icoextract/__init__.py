#!/usr/bin/env python3
"""
Windows Portable Executable (PE) icon extractor.

.. include:: ../LIB-USAGE.md
"""

import io
import logging
import os
import pathlib
import platform
import struct

import pefile

GRPICONDIRENTRY_FORMAT = ('GRPICONDIRENTRY',
    ('B,Width', 'B,Height','B,ColorCount','B,Reserved',
     'H,Planes','H,BitCount','I,BytesInRes','H,ID'))
GRPICONDIR_FORMAT = ('GRPICONDIR', ('H,Reserved', 'H,Type','H,Count'))

logger = logging.getLogger("icoextract")
logging.basicConfig()

try:
    from .version import __version__
except ImportError:
    __version__ = 'unknown'
    logger.info('icoextract: failed to read program version')

class IconExtractorError(Exception):
    """Superclass for exceptions raised by IconExtractor."""

class IconNotFoundError(IconExtractorError):
    """Exception raised when extracting an icon index or resource ID that does not exist."""

class NoIconsAvailableError(IconExtractorError):
    """Exception raised when the input program has no icon resources."""

class InvalidIconDefinitionError(IconExtractorError):
    """Exception raised when the input program has an invalid icon resource."""

class IconExtractor():
    def __init__(self, filename=None, data=None):
        """
        Loads an executable from the given `filename` or `data` (raw bytes).
        As with pefile, if both `filename` and `data` are given, `filename` takes precedence.

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

        self.groupiconres = resources.get(pefile.RESOURCE_TYPE["RT_GROUP_ICON"])
        if not self.groupiconres:
            if filename and platform.system() == "Windows":
                self._print_windows_usage_hint(filename)
            raise NoIconsAvailableError("File has no group icon resources")
        self.rticonres = resources.get(pefile.RESOURCE_TYPE["RT_ICON"])

        # Populate resources by ID
        self._group_icons = {entry.struct.Name: idx for idx, entry in enumerate(self.groupiconres.directory.entries)}
        self._icons = {icon_entry_list.id: icon_entry_list.directory.entries[0]  # Select first language
                       for icon_entry_list in self.rticonres.directory.entries}

    def list_group_icons(self) -> list[tuple[int, int]]:
        """
        Returns all group icon entries as a list of (resource ID, offset) tuples.
        """
        return [(e.struct.Name, e.struct.OffsetToData)
                for e in self.groupiconres.directory.entries]

    def _get_icon(self, index=0) -> list[tuple[pefile.Structure, bytes]]:
        """
        Returns the specified group icon in the binary.

        Result is a list of (group icon structure, icon data) tuples.
        """
        try:
            groupicon = self.groupiconres.directory.entries[index]
        except IndexError:
            raise IconNotFoundError(f"No icon exists at index {index}") from None
        resource_id = groupicon.struct.Name
        icon_lang = None
        if groupicon.struct.DataIsDirectory:
            # Select the first language from subfolders as needed.
            groupicon = groupicon.directory.entries[0]
            icon_lang = groupicon.struct.Name
            logger.debug("Picking first language %s", icon_lang)

        # Read the data pointed to by the group icon directory (GRPICONDIR) struct.
        rva = groupicon.data.struct.OffsetToData
        grp_icon_data = self._pe.get_data(rva, groupicon.data.struct.Size)
        file_offset = self._pe.get_offset_from_rva(rva)

        grp_icon_dir = self._pe.__unpack_data__(GRPICONDIR_FORMAT, grp_icon_data, file_offset)
        logger.debug("Group icon %d has ID %s and %d images: %s",
                     # pylint: disable=no-member
                     index, resource_id, grp_icon_dir.Count, grp_icon_dir)

        # pylint: disable=no-member
        if grp_icon_dir.Reserved:
            # pylint: disable=no-member
            raise InvalidIconDefinitionError("Invalid group icon definition (got Reserved=%s instead of 0)"
                % hex(grp_icon_dir.Reserved))

        # For each group icon entry (GRPICONDIRENTRY) that immediately follows, read the struct and look up the
        # corresponding icon image
        grp_icons = []
        icon_offset = grp_icon_dir.sizeof()
        for grp_icon_index in range(grp_icon_dir.Count):
            grp_icon = self._pe.__unpack_data__(
                GRPICONDIRENTRY_FORMAT, grp_icon_data[icon_offset:], file_offset+icon_offset)
            icon_offset += grp_icon.sizeof()
            logger.debug("Got group icon entry %d: %s", grp_icon_index, grp_icon)

            icon_entry = self._icons[grp_icon.ID]
            icon_data = self._pe.get_data(icon_entry.data.struct.OffsetToData, icon_entry.data.struct.Size)
            logger.debug("Got icon data for ID %d: %s", grp_icon.ID, icon_entry.data.struct)
            grp_icons.append((grp_icon, icon_data))
        return grp_icons

    def _write_ico(self, fd, num=0, resource_id=None):
        """
        Writes ICO data to a file descriptor.
        """
        if resource_id is not None:
            try:
                num = self._group_icons[resource_id]
            except KeyError:
                raise IconNotFoundError(f"No icon exists with resource ID {resource_id}") from None

        icons = self._get_icon(index=num)
        fd.write(b"\x00\x00") # 2 reserved bytes
        fd.write(struct.pack("<H", 1)) # 0x1 (little endian) specifying that this is an .ICO image
        fd.write(struct.pack("<H", len(icons)))  # number of images

        dataoffset = 6 + (len(icons) * 16)
        # First pass: write the icon dir entries
        for datapair in icons:
            group_icon, icon_data = datapair
            # Elements in ICONDIRENTRY and GRPICONDIRENTRY are all the same
            # except the last value, which is an ID in GRPICONDIRENTRY and
            # the offset from the beginning of the file in ICONDIRENTRY.
            fd.write(group_icon.__pack__()[:12])
            fd.write(struct.pack("<I", dataoffset))
            dataoffset += len(icon_data)  # Increase offset for next image

        # Second pass: write the icon data
        for datapair in icons:
            group_icon, icon_data = datapair
            fd.write(icon_data)

    def export_icon(self, filename, num=0, resource_id=None):
        """
        Exports ICO data for the requested group icon to `filename`.

        Icons can be selected by index (`num`) or resource ID. By default, the first icon in the binary is exported.
        """
        with open(filename, 'wb') as f:
            self._write_ico(f, num=num, resource_id=resource_id)

    def get_icon(self, num=0, resource_id=None) -> io.BytesIO:
        """
        Exports ICO data for the requested group icon as a `io.BytesIO` instance.

        Icons can be selected by index (`num`) or resource ID. By default, the first icon in the binary is exported.
        """
        f = io.BytesIO()
        self._write_ico(f, num=num, resource_id=resource_id)
        return f

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

__all__ = [
    'IconExtractor',
    'IconExtractorError',
    'NoIconsAvailableError',
    'InvalidIconDefinitionError'
]

__pdoc__ = {
    'scripts': False,
    'version': False,
}
