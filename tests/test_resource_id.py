#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

import unittest

import icoextract

class ResourceIDTestCase(unittest.TestCase):
    def test_resource_id(self):
        numeric_id = icoextract.ResourceID(123)
        string_id = icoextract.ResourceID(456, 'MY_APP_ICON')

        self.assertEqual(int(numeric_id), 123)
        self.assertEqual(str(numeric_id), '123')

        self.assertEqual(int(string_id), 456)
        self.assertEqual(str(string_id), 'MY_APP_ICON')

if __name__ == '__main__':
    unittest.main()
