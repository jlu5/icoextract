#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2019-2026 James Lu <james@overdrivenetworks.com>

import unittest

import icoextract.types

class ResourceIDTestCase(unittest.TestCase):
    def test_num_resource_id(self):
        numeric_id = icoextract.types.ResourceID(123)
        self.assertEqual(int(numeric_id), 123)
        self.assertEqual(str(numeric_id), '123')

    def test_string_resource_id(self):
        string_id = icoextract.types.ResourceID(456, 'MY_APP_ICON')
        self.assertEqual(int(string_id), 456)
        self.assertEqual(str(string_id), 'MY_APP_ICON')

    def test_error(self):
        with self.assertRaises(ValueError):
            icoextract.types.ResourceID(None, None)

    def test_string_only_id(self):
        str_only_id = icoextract.types.ResourceID(None, 'MY_APP_ICON')
        self.assertEqual(str(str_only_id), 'MY_APP_ICON')
        with self.assertRaises(ValueError):
            int(str_only_id)

if __name__ == '__main__':
    unittest.main()
