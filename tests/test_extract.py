#!/usr/bin/env python3

import filecmp
import os.path
import unittest

import icoextract

class UtilsTestCase(unittest.TestCase):
    def _test_extract(self, infile, target):
        # Read/write test files in tests/ folder, regardless of where working directory is
        tests_dir = os.path.dirname(__file__)
        inpath = os.path.join(tests_dir, infile)
        target = os.path.join(tests_dir, target)

        ie = icoextract.IconExtractor(inpath)

        outfile = f"tmp-{infile}.ico"
        outpath = os.path.join(tests_dir, outfile)
        ie.export_icon(outpath)

        self.assertTrue(filecmp.cmp(outpath, target),
                        f"{outpath} and {target} should be equal")
        return ie

    # App has icon + version resource
    def test_testapp64(self):
        ie = self._test_extract("testapp64.exe", "testapp.ico")
        self.assertEqual(len(ie.list_group_icons()), 1)

    # App has only version resource
    def test_testapp64_noicon(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-noicon.exe", "testapp-noicon.ico")

    # App has no resource info at all
    def test_testapp64_nores(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-nores.exe", "testapp-nores.ico")

    def test_testapp32(self):
        ie = self._test_extract("testapp32.exe", "testapp.ico")
        self.assertEqual(len(ie.list_group_icons()), 1)

    def test_testapp32_noicon(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp32-noicon.exe", "testapp-noicon.ico")

    def test_testapp32_nores(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp32-nores.exe", "testapp-nores.ico")

if __name__ == '__main__':
    unittest.main()
