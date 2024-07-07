#!/usr/bin/env python3
import os.path
import unittest

from icoextract.scripts.thumbnailer import generate_thumbnail
from PIL import Image

TESTS_DIR = os.path.dirname(__file__)
COMPARE_LENGTH = 1024  # for efficiency

class ThumbnailerTestCase(unittest.TestCase):
    def _generate_thumbnail(self, infile, outfile, **kwargs):
        infile_path = os.path.join(TESTS_DIR, infile)
        outfile_path = os.path.join(TESTS_DIR, outfile)
        generate_thumbnail(infile_path, outfile_path, **kwargs)
        return outfile_path

    def _compare_equal(self, im, orig):
        with Image.open(os.path.join(TESTS_DIR, orig)) as im_orig:
            self.assertEqual(list(im.getdata())[:COMPARE_LENGTH], list(im_orig.getdata())[:COMPARE_LENGTH],
                                "Extracted image should match original")

    def test_thumbnailer_normal(self):
        outfile = self._generate_thumbnail("testapp64.exe", "tmp-thumbnail-test-normal.png", size=128)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 128)

    def test_thumbnailer_large(self):
        outfile = self._generate_thumbnail("testapp64.exe", "tmp-thumbnail-test-large.png", size=256)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 256)
            self.assertEqual(im.height, 256)
            self._compare_equal(im, "testapp.png")

    def test_thumbnailer_with128_large(self):
        outfile = self._generate_thumbnail("testapp64-with128.exe", "tmp-thumbnail-test-with-128-large.png", size=256)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 256)
            self.assertEqual(im.height, 256)
            self._compare_equal(im, "testapp.png")

    def test_thumbnailer_with128_normal(self):
        outfile = self._generate_thumbnail("testapp64-with128.exe", "tmp-thumbnail-test-with-128-normal.png", size=128)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 128)
            self._compare_equal(im, "tmp-testapp-128.png")

    def test_thumbnailer_smallonly(self):
        outfile = self._generate_thumbnail("testapp32-smallonly.exe", "tmp-thumbnail-test-smallonly.png", size=128)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 48)
            self.assertEqual(im.height, 48)
            self._compare_equal(im, "tmp-testapp-48.bmp")

    def test_thumbnailer_force_resize(self):
        outfile = self._generate_thumbnail("testapp32-smallonly.exe", "tmp-thumbnail-force-resize.png", size=128,
                                           force_resize=True)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 128)

    def test_192_normal(self):
        """Test that exe files with oddly sized icons (192x192) are wrapped to the expected dimensions"""
        outfile = self._generate_thumbnail("testapp64-with192.exe", "tmp-thumbnail-192-normal.png", size=128)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 128)
            self._compare_equal(im, "tmp-testapp-128.png")

    def test_192_large(self):
        """Test that exe files with oddly sized icons (192x192) are wrapped to the expected dimensions"""
        outfile = self._generate_thumbnail("testapp64-with192.exe", "tmp-thumbnail-192-large.png", size=256)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 192)
            self.assertEqual(im.height, 192)

    def test_unsupported_output_size_too_large(self):
        """Test an invalid requested icon size (> 256)"""
        outfile = self._generate_thumbnail("testapp64.exe", "tmp-thumbnail-test-unsupported-size-too-large.png",
        size=300)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 256)
            self.assertEqual(im.height, 256)
            self._compare_equal(im, "testapp.png")

    def test_unsupported_output_size_too_small(self):
        """Test an invalid requested icon size (< 128)"""
        outfile = self._generate_thumbnail("testapp64.exe", "tmp-thumbnail-test-unsupported-size-too-small.png",
        size=64)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 128)
            self._compare_equal(im, "tmp-testapp-128.png")

    def test_unsupported_output_size_between(self):
        """Test an invalid requested icon size (> 128, < 256)"""
        outfile = self._generate_thumbnail("testapp64.exe", "tmp-thumbnail-test-unsupported-size-between.png",
        size=200)
        with Image.open(outfile) as im:
            self.assertEqual(im.width, 128)
            self.assertEqual(im.height, 128)
            self._compare_equal(im, "tmp-testapp-128.png")

if __name__ == '__main__':
    unittest.main()
