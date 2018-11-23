# -*- coding: utf-8 -*-
"""
@create: 2018-11-14 20:12:49.

@author: key_public

@desc: key_public
"""
import re
import six
import ecdsa
import hashlib
import binascii
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa import SECP256k1
from ecdsa.numbertheory import order_mod
from ecdsa.numbertheory import inverse_mod
from ecdsa.curves import orderlen as orderlen_f
from pyeosio_ecc import key_utils
from pyeosio_ecc.exceptions import InputInvaild
from pyeosio_ecc.exceptions import SignatureInvaild


def _signdecode(signature):
    '''signdecode.

    @arg {string} signature - like SIG_K1_base58signature..
    @throws {Error} invalid
    @return {Signature}
    '''
    assert isinstance(signature, six.string_types)
    match = re.match(r'^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$', signature)
    assert match and len(match.groups()) == 2, 'Expecting signature like: SIG_K1_base58signature..'  # noqa
    keyType = match.group(1)
    keyString = match.group(2)
    assert keyType == 'K1', 'K1 private key expected'
    return key_utils.check_decode(keyString, keyType)


def _recover_key(digest, signature, i):
    ''' Recover the public key from the sig
        http://www.secg.org/sec1-v2.pdf
    '''
    curve = ecdsa.SECP256k1.curve
    G = ecdsa.SECP256k1.generator
    order = ecdsa.SECP256k1.order
    yp = (i % 2)
    r, s = ecdsa.util.sigdecode_string(signature, order)
    x = r + (i // 2) * order
    alpha = ((x * x * x) + (curve.a() * x) + curve.b()) % curve.p()
    beta = ecdsa.numbertheory.square_root_mod_prime(alpha, curve.p())
    y = beta if (beta - yp) % 2 == 0 else curve.p() - beta
    # generate R
    R = ecdsa.ellipticcurve.Point(curve, x, y, order)
    e = ecdsa.util.string_to_number(digest)
    # compute Q
    Q = ecdsa.numbertheory.inverse_mod(
        r, order) * (s * R + (-e % order) * G)
    # verify message
    vk = ecdsa.VerifyingKey.from_public_point(Q, curve=ecdsa.SECP256k1)
    if not vk.verify_digest(
            signature, digest,
            sigdecode=ecdsa.util.sigdecode_string):
        return None
    return vk


def compress_pubkey(pubkey, compressed=True):
    ''' '''
    # order = self._sk.curve.generator.order()
    assert isinstance(pubkey, VerifyingKey)
    order = pubkey.curve.order
    p = pubkey.pubkey.point

    x_str = ecdsa.util.number_to_string(p.x(), order)

    if compressed:
        # 0x03 isEven 0x02 isNotEven
        hex_data = bytearray(chr(2 + (p.y() & 1)), 'utf-8')
        # _compressed = binascii.hexlify(hex_data + x_str).decode()
        _compressed = bytes(hex_data + x_str)
    else:
        hex_data = bytearray(chr(4), 'utf-8')
        y_str = ecdsa.util.number_to_string(p.y(), order)
        # _compressed = binascii.hexlify(hex_data + x_str + y_str).decode()
        _compressed = bytes(hex_data + x_str + y_str)
    return _compressed


def uncompress_pubkey(buffer, curve):
    ''' '''
    # order = self._sk.curve.generator.order()
    # 024ea8b06ce3d42d8836581fcd021462ae725ba82718e4424fa6494205a2d5003a
    # x: 35578450139401997169515814554720978776166223702831381120147644166809836650554 # noqa
    # 115792089237316195423570985008687907853269984665640564039457584007908834671662
    # alpha: 4581825507844992844157016009473037419679996425548721709611050323991906313294  # noqa
    # beta: 65197393367748915602384483603671237051715670494505581478000920488137854211910  # noqa
    # (35578450139401997169515814554720978776166223702831381120147644166809836650554,65197393367748915602384483603671237051715670494505581478000920488137854211910)

    assert isinstance(buffer, six.binary_type)
    comptype = buffer[0]
    compressed = buffer[0] != 0x4
    order = curve.order
    orderlen = orderlen_f(order)
    _curve = curve.curve

    x = ecdsa.util.string_to_number(buffer[1: 1 + orderlen])

    if compressed:
        assert len(buffer) == (orderlen + 1), 'Invalid sequence length'
        assert comptype == 0x2 or comptype == 0x3, 'Invalid sequence tag'
        isodd = comptype == 0x03

        # yp = (isodd % 2)
        alpha = ((x * x * x) + (_curve.a() * x) + _curve.b()) % _curve.p()
        beta = ecdsa.numbertheory.square_root_mod_prime(alpha, _curve.p())
        beta_iseven = beta % 2 == 0
        y = beta if beta_iseven ^ (1 if isodd else 0) else _curve.p() - beta
    else:
        y = ecdsa.util.string_to_number(buffer[1 + orderlen:])

    Q = ecdsa.ellipticcurve.Point(_curve, x, y, order)
    return ecdsa.VerifyingKey.from_public_point(Q, curve=curve)


class PublicKey(object):
    """PublicKey."""

    def __init__(self, vk, pubkey_prefix='EOS'):
        """__init__."""
        assert isinstance(vk, VerifyingKey)
        assert isinstance(pubkey_prefix, six.string_types)

        self.pubkey_prefix = pubkey_prefix
        self._vk = vk

    def to_public(self):
        cmp = compress_pubkey(self._vk)
        return self.pubkey_prefix + key_utils.check_encode(cmp)

    def to_string(self):
        return self.to_public()

    def verify(self, sign, content):
        return self._vk.verify_digest(sign, content,
                                      sigdecode=ecdsa.util.sigdecode_string)

    # ----------------------------------------------
    #        create pubkey
    # ----------------------------------------------

    @classmethod
    def recover(cls, digest, signature, encoding='utf8'):
        sign = _signdecode(signature)
        recover_param = six.byte2int(sign[:1]) - 4 - 27
        signdata = sign[1:]

        if isinstance(digest, six.string_types):
            digest = digest.encode(encoding)

        digest = hashlib.sha256(digest).digest()

        pubkey = _recover_key(digest, signdata, recover_param)
        if not pubkey:
            raise SignatureInvaild('sign invaild')

        return PublicKey(pubkey)

    @classmethod
    def is_valid(cls, pubkey, pubkey_prefix='EOS'):
        '''
            @param {string|Buffer|PublicKey|ecurve.Point} pubkey - public key
            @param {string} [pubkey_prefix = 'EOS']
        '''
        try:
            cls.from_string(pubkey, pubkey_prefix)
            return True
        except Exception:
            return False

    @classmethod
    def from_binary(cls, buffer, pubkey_prefix='EOS'):
        # return PublicKey.fromBuffer(new Buffer(bin, 'binary'))
        return cls.from_buffer(buffer, pubkey_prefix)

    @classmethod
    def from_buffer(cls, buffer, pubkey_prefix='EOS'):
        # return PublicKey(ecurve.Point.decodeFrom(secp256k1, buffer))
        return PublicKey(uncompress_pubkey(buffer, SECP256k1), pubkey_prefix)

    @classmethod
    def from_point(cls, point, pubkey_prefix='EOS'):
        # return PublicKey(point)
        assert isinstance(point, ecdsa.ellipticcurve.Point)
        return PublicKey(ecdsa.VerifyingKey.from_public_point(
            point, curve=SECP256k1), pubkey_prefix)

    # @classmethod
    # def from_hex(cls, hexstr):
    #     # return PublicKey.fromBuffer(new Buffer(hex, 'hex'))
    #     raise NotImplementedError

    # @classmethod
    # def from_string_hex(cls, hexstr):
    #     # return PublicKey.fromString(new Buffer(hex, 'hex'))
    #     raise NotImplementedError

    @classmethod
    def from_string(cls, pubkey, pubkey_prefix='EOS'):
        '''
            @arg {string} public_key - like PUB_K1_base58pubkey..
            @arg {string} [pubkey_prefix= 'EOS'] - public key prefix
            @return PublicKey or `null` (invalid)
        '''
        try:
            return cls.from_stringorthrow(pubkey, pubkey_prefix='EOS')
        except Exception:
            return None

    @classmethod
    def from_stringorthrow(cls, pubkey, pubkey_prefix='EOS'):
        '''
            @arg {string} public_key - like PUB_K1_base58pubkey..
            @arg {string} [pubkey_prefix = 'EOS'] - public key prefix
            @throws {Error} if public key is invalid
            @return PublicKey
        '''
        assert isinstance(pubkey, six.string_types)
        match = re.match(r'^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)$', pubkey)
        if match is None:
            prefix_match = re.match(r'^' + pubkey_prefix, pubkey)
            if prefix_match:
                pubkey = pubkey[len(pubkey_prefix):]
                return cls.from_buffer(key_utils.check_decode(pubkey))

        assert len(match.groups()) == 3, 'Expecting public key like: PUB_K1_base58pubkey..'  # noqa
        keyType = match.group(1)
        keyString = match.group(2)
        assert keyType == 'K1', 'K1 private key expected'
        return cls.from_buffer(key_utils.check_decode(keyString, keyType))

    @classmethod
    def from_(cls, obj, pubkey_prefix='EOS'):
        if isinstance(obj, six.string_types):
            return cls.from_string(obj, pubkey_prefix)
        elif isinstance(obj, six.binary_type):
            return cls.from_buffer(obj, pubkey_prefix)
        elif isinstance(obj, ecdsa.ellipticcurve.Point):
            return cls.from_point(obj, pubkey_prefix)
        else:
            raise TypeError('from_ obj invaild')
