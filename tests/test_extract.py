#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

import filecmp
import os.path
import unittest

try:
    import nefile
except ImportError:
    nefile = None

import icoextract

class _BaseIconExtractorTestCase(unittest.TestCase):
    def get_test_file(self, filename):
        # Read/write test files in tests/ folder, regardless of where working directory is
        tests_dir = os.path.dirname(__file__)
        return os.path.join(tests_dir, filename)

    def _test_extract(self, infile, compare_against=None, **kwargs):
        """
        Wrapper to test extracting a single icon from infile, and comparing
        the output with an existing .ico file
        """
        inpath = self.get_test_file(infile)
        ie = icoextract.IconExtractor(inpath)
        outpath = self.get_test_file(f"tmp-extract-{infile}.ico")
        ie.export_icon(outpath, **kwargs)

        assert compare_against, \
            "Successful extractions should have a file to compare against"
        compare_against = self.get_test_file(compare_against)
        self.assertTrue(filecmp.cmp(outpath, compare_against),
                        f"{outpath} and {compare_against} should be equal")
        return ie

class PEIconExtractorTestCase(_BaseIconExtractorTestCase):
    def test_basic(self):
        """Test basic extraction cases"""
        for app in ["testapp64.exe", "testapp32.exe"]:
            with self.subTest(app=app):
                ie = self._test_extract(app, "testapp.ico")

                # Nonexistent icon index
                with self.assertRaises(icoextract.IconNotFoundError):
                    self._test_extract(app, num=10)

    def test_list(self):
        """Test list_group_icons() behaviour"""
        for app in ["testapp64.exe", "testapp32.exe"]:
            with self.subTest(app=app):
                inpath = self.get_test_file(app)
                ie = icoextract.IconExtractor(inpath)

                icon_list = ie.list_group_icons()
                self.assertEqual(len(icon_list), 1)
                resource_id, grp_icons_with_offsets = icon_list[0]
                self.assertEqual(int(resource_id), 2)  # ID
                self.assertEqual(len(grp_icons_with_offsets), 4)  # number of icons
                expected_sizes = [(0, 0), (16, 16), (32, 32), (48, 48)]
                real_sizes = [
                    (grp_icons_dir_entry.Width, grp_icons_dir_entry.Height)
                    for (grp_icons_dir_entry, resource_offset, file_offset)
                    in grp_icons_with_offsets
                ]
                self.assertCountEqual(expected_sizes, real_sizes)

    def test_no_icons(self):
        """Test that NoIconsAvailableError is raised when the input binary has
        no icons"""
        cases = [
            # App has only version resource
            "testapp64-noicon.exe", "testapp32-noicon.exe",
            # App has no resource info at all
            "testapp32-nores.exe", "testapp32-nores.exe"
        ]
        for app in cases:
            with self.subTest(app=app):
                with self.assertRaises(icoextract.NoIconsAvailableError):
                    self._test_extract(app)

    def test_fd_as_input(self):
        """Test passing binary input into IconExtractor directly"""
        tests_dir = os.path.dirname(__file__)
        with open(os.path.join(tests_dir, "testapp64.exe"), 'rb') as f:
            ie = icoextract.IconExtractor(data=f.read())
            self.assertEqual(len(ie.list_group_icons()), 1)

    def test_extract_icon_id(self):
        """Test extracting an icon by its resource ID"""
        self._test_extract("testapp64.exe", "testapp.ico", resource_id=2)

        # ID does not exist
        with self.assertRaises(icoextract.IconNotFoundError):
            self._test_extract("testapp64.exe", resource_id=1337)

        # ID is not an icon
        with self.assertRaises(icoextract.IconNotFoundError):
            self._test_extract("testapp64.exe", resource_id=1)

    def test_extract_icon_id_string(self):
        """Test extracting an icon with a string resource ID"""
        # Default index should pick up the icon
        self._test_extract("testapp64-string-res.exe", "testapp.ico")

        ie = self._test_extract("testapp64-string-res.exe", "testapp.ico",
                                resource_id="MY_APP_ICON")

        # ID does not exist
        with self.assertRaises(icoextract.IconNotFoundError):
            self._test_extract("testapp64.exe", resource_id="nonexistent")
        with self.assertRaises(icoextract.IconNotFoundError):
            self._test_extract("testapp64.exe", resource_id=5)

        icon_list = ie.list_group_icons()
        self.assertEqual(len(icon_list), 1)
        self.assertEqual(str(icon_list[0][0]), "MY_APP_ICON")
        self.assertGreater(int(icon_list[0][0]), 0)

@unittest.skipUnless(nefile, "nefile library is not installed")
class NEIconExtractorTestCase(_BaseIconExtractorTestCase):
    def test_win16_basic(self):
        """Test basic extraction cases"""
        self._test_extract("testapp16.exe", "testapp-bpp.ico")
        self._test_extract("testapp16.exe", "testapp-bpp.ico", resource_id="IDI_APPICON")

        # Invalid IDs
        with self.assertRaises(icoextract.IconNotFoundError):
            self._test_extract("testapp64.exe", resource_id=1337)
        with self.assertRaises(icoextract.IconNotFoundError):
            self._test_extract("testapp64.exe", resource_id="FOO")

    def test_win16_no_icons(self):
        """Test programs with no icons"""
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-noicon.exe")
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-nores.exe")

    def test_list(self):
        """Test that list_group_icons() returns the right metadata"""
        inpath = self.get_test_file("testapp16.exe")
        ie = icoextract.IconExtractor(inpath)

        icon_list = ie.list_group_icons()
        self.assertEqual(len(icon_list), 1)
        resource_id, grp_icons_with_offsets = icon_list[0]
        self.assertEqual(str(resource_id), "IDI_APPICON")  # ID
        self.assertEqual(len(grp_icons_with_offsets), 2)  # number of icons

        for (grp_icons_dir_entry, _, _) in grp_icons_with_offsets:
            self.assertEqual(grp_icons_dir_entry.Width, 32)
            self.assertEqual(grp_icons_dir_entry.Height, 32)


if __name__ == '__main__':
    unittest.main()
