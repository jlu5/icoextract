#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

import filecmp
import os.path
import unittest

import icoextract

class IconExtractorTestCase(unittest.TestCase):
    def _test_extract(self, infile, compare_against=None, **kwargs):
        """
        Wrapper to test extracting a single icon from infile, and comparing
        the output with an existing .ico file
        """
        # Read/write test files in tests/ folder, regardless of where working directory is
        tests_dir = os.path.dirname(__file__)
        inpath = os.path.join(tests_dir, infile)

        ie = icoextract.IconExtractor(inpath)

        outfile = f"tmp-{infile}.ico"
        outpath = os.path.join(tests_dir, outfile)
        ie.export_icon(outpath, **kwargs)

        assert compare_against, \
            "Successful extractions should have a file to compare against"
        compare_against = os.path.join(tests_dir, compare_against)
        self.assertTrue(filecmp.cmp(outpath, compare_against),
                        f"{outpath} and {compare_against} should be equal")
        return ie

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
                tests_dir = os.path.dirname(__file__)
                inpath = os.path.join(tests_dir, app)
                ie = icoextract.IconExtractor(inpath)

                icon_list = ie.list_group_icons()
                self.assertEqual(len(icon_list), 1)
                resource_id, grp_icons_with_offsets = icon_list[0]
                self.assertEqual(resource_id, 2)  # ID
                self.assertEqual(len(grp_icons_with_offsets), 4)  # number of icons
                expected_sizes = [(0, 0), (16, 16), (32, 32), (48, 48)]
                real_sizes = [
                    (grp_icons_dir_entry.Width, grp_icons_dir_entry.Height)
                    for (grp_icons_dir_entry, resource_offset, file_offset)
                    in grp_icons_with_offsets
                ]
                self.assertCountEqual(expected_sizes, real_sizes)

    def test_no_icon_resource(self):
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

if __name__ == '__main__':
    unittest.main()
