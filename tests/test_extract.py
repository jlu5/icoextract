#!/usr/bin/env python3

import filecmp
import unittest

import icoextract

class UtilsTestCase(unittest.TestCase):
    def _test_extract(self, infile, target):
        ie = icoextract.IconExtractor(infile)

        outfile = f"tmp-{infile}.ico"
        ie.export_icon(outfile)

        self.assertTrue(filecmp.cmp(outfile, target),
                        f"{outfile} and {target} should be equal")

    # App has icon + version resource
    def test_testapp64(self):
        self._test_extract("testapp64.exe", "testapp.ico")

    # App has only version resource
    def test_testapp64_noicon(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-noicon.exe", "testapp-noicon.ico")

    # App has no resource info at all
    def test_testapp64_nores(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp64-nores.exe", "testapp-nores.ico")

    def test_testapp32(self):
        self._test_extract("testapp32.exe", "testapp.ico")

    def test_testapp32_noicon(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp32-noicon.exe", "testapp-noicon.ico")

    def test_testapp32_nores(self):
        with self.assertRaises(icoextract.NoIconsAvailableError):
            self._test_extract("testapp32-nores.exe", "testapp-nores.ico")

if __name__ == '__main__':
    unittest.main()
