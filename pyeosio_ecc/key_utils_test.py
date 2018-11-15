# -*- coding: utf-8 -*-

import os
import unittest

try:
    from pyeosio_ecc import key_utils
except ImportError:
    import sys
    sys.path.insert(0, os.getcwd())
    from pyeosio_ecc import key_utils

# fpath = os.path.abspath(os.path.dirname(__file__))


class TestMathFunc(unittest.TestCase):
    """Test mathfuc.py"""

    def test_a_init(self):
        testdata = b'aaa'
        encodedata = '4h36xLruYA'
        result = key_utils.check_encode(testdata)
        self.assertEqual(encodedata, result)
        result2 = key_utils.check_decode(result)
        self.assertEqual(testdata, result2)


if __name__ == '__main__':
    unittest.main()
