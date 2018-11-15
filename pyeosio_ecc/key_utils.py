# -*- coding: utf-8 -*-
"""
@create: 2018-11-14 19:35:49.

@author: key_utils

@desc: key_utils
"""
import six
import base58
import hashlib
import binascii
from pyeosio_ecc.exceptions import InputInvaild


def ripemd160(data):
    ''' '''
    # h = hashlib.new('ripemd160')
    h = hashlib.new('rmd160')
    h.update(data)
    return h.digest()


def check_encode(keystr, keytype=None):
    assert isinstance(keystr, six.binary_type)
    assert keytype is None or isinstance(keytype, six.string_types)

    if keytype == 'sha256x2':
        sha256one = hashlib.sha256(keystr).digest()
        checksum = hashlib.sha256(sha256one).digest()[0:-4]
        return base58.b58encode(keystr + checksum).decode()
    else:
        check = keystr
        if keytype:
            check += keytype.encode()

        checksum = ripemd160(check)[:4]
        return base58.b58encode(keystr + checksum).decode()


def check_decode(keystr, keytype=None):
    assert isinstance(keystr, six.string_types)
    assert keytype is None or isinstance(keytype, six.string_types)

    # keystr = six.b(keystr)
    # keystr = binascii.unhexlify(keystr)
    keystr = base58.b58decode(keystr)
    checksum = keystr[-4:]
    keystr = keystr[0:-4]

    if keytype == 'sha256x2':
        sha256one = hashlib.sha256(keystr).digest()
        newcheck = hashlib.sha256(sha256one).digest()[0:-4]
    else:
        check = keystr
        if keytype:
            check += keytype.encode()

        h = hashlib.new('ripemd160')
        h.update(check)
        newcheck = h.digest()[:4]

    if checksum != newcheck:
        raise InputInvaild('checksum invaild')

    return keystr
