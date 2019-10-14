"""
Windows PE EXE icon extractor.
"""

import io
import pefile
import sys
import struct

GRPICONDIRENTRY_FORMAT = ('GRPICONDIRENTRY',
    ('B,Width', 'B,Height','B,ColorCount','B,Reserved',
     'H,Planes','H,BitCount','I,BytesInRes','H,ID'))
GRPICONDIR_FORMAT = ('GRPICONDIR', ('H,Reserved', 'H,Type','H,Count'))

class IconExtractor():
    def __init__(self, filename):
        self.filename = filename
        # Use fast loading and explicitly load the RESOURCE directory entry. This saves a LOT of time
        # on larger files
        self._pe = pefile.PE(filename, fast_load=True)
        self._pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])

        # Reverse the list of entries before making the mapping so that earlier values take precedence
        # When an executable includes multiple icon resources, we should use only the first one.
        resources = {rsrc.id: rsrc for rsrc in reversed(self._pe.DIRECTORY_ENTRY_RESOURCE.entries)}

        self.groupiconres = resources.get(pefile.RESOURCE_TYPE["RT_GROUP_ICON"])
        self.rticonres = resources.get(pefile.RESOURCE_TYPE["RT_ICON"])

    def _get_group_icon_entries(self, minsize=32):
        """
        Returns the group icon entries for the first group icon in the executable.
        """
        groupicon = self.groupiconres
        while groupicon.struct.DataIsDirectory:
            # Select the first icon and language from subfolders as needed.
            groupicon = groupicon.directory.entries[0]

        # Read the data pointed to by the group icon directory (GRPICONDIR) struct.
        resource_offset = groupicon.data.struct.OffsetToData
        size = groupicon.data.struct.Size
        data = self._pe.get_memory_mapped_image()[resource_offset:resource_offset+size]
        file_offset = self._pe.get_offset_from_rva(resource_offset)

        grp_icon_dir = self._pe.__unpack_data__(GRPICONDIR_FORMAT, data, file_offset)
        print(grp_icon_dir)

        # For each group icon entry (GRPICONDIRENTRY) that immediately follows, read its data and save it.
        grp_icons = []
        icon_offset = grp_icon_dir.sizeof()
        for idx in range(grp_icon_dir.Count):
            grp_icon = self._pe.__unpack_data__(GRPICONDIRENTRY_FORMAT, data[icon_offset:], file_offset+icon_offset)
            icon_offset += grp_icon.sizeof()
            if (grp_icon.Width or 256) >= minsize:
                print("Got logical group icon", grp_icon)
                grp_icons.append(grp_icon)
            else:
                print("Skipped logical group icon", grp_icon)

        return grp_icons

    def _get_icon_data(self, icon_ids):
        """
        Return a list of raw icon images corresponding to the icon IDs given.
        """
        icons = []
        for idx, icon_entry_list in enumerate(self.rticonres.directory.entries):

            if icon_entry_list.id in icon_ids:
                icon_entry = icon_entry_list.directory.entries[0]  # Select first language
                resource_offset = icon_entry.data.struct.OffsetToData
                size = icon_entry.data.struct.Size
                data = self._pe.get_memory_mapped_image()[resource_offset:resource_offset+size]
                print(f"Exported icon with ID {icon_entry_list.id}: {icon_entry.struct}")
                icons.append(data)
        return icons

    def _write_ico(self, fd):
        """
        Writes ICO data to a file descriptor.
        """
        group_icons = self._get_group_icon_entries()
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

    def export_icon(self, fname):
        """
        Writes ICO data containing the program icon of the input executable.
        """
        with open(fname, 'wb') as f:
            self._write_ico(f)

    def get_icon(self):
        """
        Returns ICO data as a BytesIO() instance, containing the program icon of the input executable.
        """
        f = io.BytesIO()
        self._write_ico(f)
        return f

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="input filename")
    parser.add_argument("output", help="output filename")
    args = parser.parse_args()

    extractor = IconExtractor(args.input)
    extractor.export_icon(args.output)