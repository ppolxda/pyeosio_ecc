# -*- coding: utf-8 -*-

import os
import unittest

try:
    from pyeosio_ecc import key_public
except ImportError:
    import sys
    sys.path.insert(0, os.getcwd())
    from pyeosio_ecc import key_public

# fpath = os.path.abspath(os.path.dirname(__file__))


class TestMathFunc(unittest.TestCase):
    """Test mathfuc.py"""

    def test_a_init(self):
        pubkey = 'EOS8LSJ3oPe5KSY64Ds22Mw7sVWYHUYijEQKb8sBhfTQL7UTSLLZL'
        pubkey2 = key_public.PublicKey.from_string(pubkey)
        self.assertEqual(pubkey, pubkey2.to_string())


if __name__ == '__main__':
    unittest.main()
