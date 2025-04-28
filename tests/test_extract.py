#!/usr/bin/env python3

import filecmp
import os.path
import unittest

import icoextract

class UtilsTestCase(unittest.TestCase):
    def _test_extract(self, infile, compare_against=None):
        # Read/write test files in tests/ folder, regardless of where working directory is
        tests_dir = os.path.dirname(__file__)
        inpath = os.path.join(tests_dir, infile)

        ie = icoextract.IconExtractor(inpath)

        outfile = f"tmp-{infile}.ico"
        outpath = os.path.join(tests_dir, outfile)
        ie.export_icon(outpath)

        assert compare_against, \
            "Successful extractions should have a file to compare against"
        compare_against = os.path.join(tests_dir, compare_against)
        self.assertTrue(filecmp.cmp(outpath, compare_against),
                        f"{outpath} and {compare_against} should be equal")
        return ie

    # App has icon + version resource
    def test_testapp64(self):
        ie = self._test_extract("testapp64.exe", "testapp.ico")
        self.assertEqual(len(ie.list_group_icons()), 1)

    # App has only version resource
    def test_testapp64_noicon(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-noicon.exe")

    # App has no resource info at all
    def test_testapp64_nores(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-nores.exe")

    def test_testapp32(self):
        ie = self._test_extract("testapp32.exe", "testapp.ico")
        self.assertEqual(len(ie.list_group_icons()), 1)

    def test_testapp32_noicon(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp32-noicon.exe")

    def test_testapp32_nores(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp32-nores.exe")

    def test_fd_as_input(self):
        tests_dir = os.path.dirname(__file__)
        with open(os.path.join(tests_dir, "testapp64.exe"), 'rb') as f:
            ie = icoextract.IconExtractor(data=f.read())
            self.assertEqual(len(ie.list_group_icons()), 1)

if __name__ == '__main__':
    unittest.main()
