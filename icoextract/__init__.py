#!/usr/bin/env python3
"""
Windows PE EXE icon extractor.
"""

import io
import logging
import sys
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
    pass
class NoIconsAvailableError(IconExtractorError):
    pass
class InvalidIconDefinitionError(IconExtractorError):
    pass

class IconExtractor():
    def __init__(self, filename):
        self.filename = filename
        # Use fast loading and explicitly load the RESOURCE directory entry. This saves a LOT of time
        # on larger files
        self._pe = pefile.PE(filename, fast_load=True)
        self._pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])

        if not hasattr(self._pe, 'DIRECTORY_ENTRY_RESOURCE'):
            raise NoIconsAvailableError(f"{filename} has no resources")

        # Reverse the list of entries before making the mapping so that earlier values take precedence
        # When an executable includes multiple icon resources, we should use only the first one.
        resources = {rsrc.id: rsrc for rsrc in reversed(self._pe.DIRECTORY_ENTRY_RESOURCE.entries)}

        self.groupiconres = resources.get(pefile.RESOURCE_TYPE["RT_GROUP_ICON"])
        if not self.groupiconres:
            raise NoIconsAvailableError(f"{filename} has no group icon resources")
        self.rticonres = resources.get(pefile.RESOURCE_TYPE["RT_ICON"])

    def list_group_icons(self):
        """
        Returns a list of group icon entries.
        """
        return [(e.struct.Name, e.struct.OffsetToData)
                for e in self.groupiconres.directory.entries]

    def _get_group_icon_entries(self, num=0):
        """
        Returns the group icon entries for the specified group icon in the executable.
        """
        groupicon = self.groupiconres.directory.entries[num]
        if groupicon.struct.DataIsDirectory:
            # Select the first language from subfolders as needed.
            groupicon = groupicon.directory.entries[0]

        # Read the data pointed to by the group icon directory (GRPICONDIR) struct.
        rva = groupicon.data.struct.OffsetToData
        size = groupicon.data.struct.Size
        data = self._pe.get_data(rva, size)
        file_offset = self._pe.get_offset_from_rva(rva)

        grp_icon_dir = self._pe.__unpack_data__(GRPICONDIR_FORMAT, data, file_offset)
        logger.debug(grp_icon_dir)

        if grp_icon_dir.Reserved:
            raise InvalidIconDefinitionError("Invalid group icon definition (got Reserved=%s instead of 0)" % hex(grp_icon_dir.Reserved))

        # For each group icon entry (GRPICONDIRENTRY) that immediately follows, read its data and save it.
        grp_icons = []
        icon_offset = grp_icon_dir.sizeof()
        for idx in range(grp_icon_dir.Count):
            grp_icon = self._pe.__unpack_data__(GRPICONDIRENTRY_FORMAT, data[icon_offset:], file_offset+icon_offset)
            icon_offset += grp_icon.sizeof()
            grp_icons.append(grp_icon)
            logger.debug("Got logical group icon %s", grp_icon)

        return grp_icons

    def _get_icon_data(self, icon_ids):
        """
        Return a list of raw icon images corresponding to the icon IDs given.
        """
        icons = []
        icon_entry_lists = {icon_entry_list.id: icon_entry_list for icon_entry_list in self.rticonres.directory.entries}
        for icon_id in icon_ids:
            icon_entry_list = icon_entry_lists[icon_id]

            icon_entry = icon_entry_list.directory.entries[0]  # Select first language
            rva = icon_entry.data.struct.OffsetToData
            size = icon_entry.data.struct.Size
            data = self._pe.get_data(rva, size)
            logger.debug(f"Exported icon with ID {icon_entry_list.id}: {icon_entry.struct}")
            icons.append(data)
        return icons

    def _write_ico(self, fd, num=0):
        """
        Writes ICO data to a file descriptor.
        """
        group_icons = self._get_group_icon_entries(num=num)
        icon_images = self._get_icon_data([g.ID for g in group_icons])
        icons = list(zip(group_icons, icon_images))
        assert len(group_icons) == len(icon_images)
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

    def export_icon(self, fname, num=0):
        """
        Writes ICO data containing the program icon of the input executable.
        """
        with open(fname, 'wb') as f:
            self._write_ico(f, num=num)

    def get_icon(self, num=0):
        """
        Returns ICO data as a BytesIO() instance, containing the program icon of the input executable.
        """
        f = io.BytesIO()
        self._write_ico(f, num=num)
        return f

__all__ = ['IconExtractor']
