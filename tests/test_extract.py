#!/usr/bin/env python3

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
                self.assertEqual(len(ie.list_group_icons()), 1)

                # Nonexistent icon index
                with self.assertRaises(icoextract.IconNotFoundError):
                    self._test_extract(app, num=10)

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

if __name__ == '__main__':
    unittest.main()
