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

    def test_testapp32(self):
        self._test_extract("testapp32.exe", "testapp.ico")

    def test_testapp64(self):
        self._test_extract("testapp64.exe", "testapp.ico")

if __name__ == '__main__':
    unittest.main()
