# -*- coding: utf-8 -*-
"""
@create: 2018-11-15 18:39:03.

@author: signature

@desc: signature
"""
# import re
# import six
# import hashlib
# from pyeosio_ecc import key_utils
# from pyeosio_ecc.key_public import PublicKey


# class Signature(object):

#     def __init__(self, signdata):
#         self.signdata = signdata

#     def verify(self, data, pubkey, encoding='utf8'):
#         '''Verify signed data.

#         @arg {String | Buffer} data - full data
#         @arg {pubkey | PublicKey} pubkey - EOSKey..
#         @arg {String} [encoding = 'utf8'] - data encoding (if data is a string)
#         @return {boolean}
#         '''
#         #   function verify() {
#         #         if(typeof data == = 'string') {
#         #             data = Buffer.from(data, encoding)
#         #         }
#         #        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
#         #        data = hash.sha256(data)
#         #        return verifyHash(data, pubkey)
#         #        }
#         raise NotImplementedError

#     def verify_hash(self, dataSha256, pubkey, encoding='hex'):
#         '''Verify a buffer of exactally 32 bytes in size (sha256(text))

#         @arg {String|Buffer} dataSha256 - 32 byte buffer or string
#         @arg {String|PublicKey} pubkey - EOSKey..
#         @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

#         @return {boolean}
#         '''
#         # function () {
#         #     if(typeof dataSha256 === 'string') {
#         #         dataSha256 = Buffer.from(dataSha256, encoding)
#         #     }
#         #     if(dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256))
#         #         throw new Error("dataSha256: 32 bytes required")

#         #     const publicKey = PublicKey(pubkey)
#         #     assert(publicKey, 'pubkey required')

#         #     return ecdsa.verify(
#         #         curve, dataSha256,
#         #         { r: r, s: s },
#         #         publicKey.Q
#         #     );
#         # };
#         raise NotImplementedError

#     def verify_hex(self, _hex, pubkey):
#         '''Verify hex data by converting to a buffer then hashing.

#         @return {boolean}
#         '''
#         # function verifyHex() {
#         #     console.log('Deprecated: use verify(data, pubkey, "hex")');

#         #     const buf = Buffer.from(hex, 'hex');
#         #     return verify(buf, pubkey);
#         # };
#         raise NotImplementedError

#     @classmethod
#     def recover(self, data, encoding='utf8'):
#         '''Recover the public key used to create this signature using full data.

#         @arg {String|Buffer} data - full data
#         @arg {String} [encoding = 'utf8'] - data encoding (if string)

#         @return {PublicKey}
#         '''
#         if isinstance(datasha256, six.string_types):
#             datasha256 = datasha256.encode(encoding)

#         if len(datasha256) != 32 or isinstance(datasha256, six.binary_type):
#             raise TypeError("dataSha256: 32 byte String or buffer requred")

#         data = hashlib.sha256(datasha256).digest()
#         return self.recover_hash(data)

#     def recover_hash(self, datasha256, encoding='hex'):
#         '''Hash and sign arbitrary data.

#         @arg {String|Buffer} dataSha256 - sha256 hash 32 byte buffer or hex string
#         @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

#         @return {PublicKey}
#         '''
#         if isinstance(datasha256, six.string_types):
#             datasha256 = six.b(datasha256)

#         if len(datasha256) != 32 or isinstance(datasha256, six.binary_type):
#             raise TypeError("dataSha256: 32 byte String or buffer requred")

#         return PublicKey.recover(datasha256, self.signdata)

#     # ----------------------------------------------
#     #        class api
#     # ----------------------------------------------

#     @classmethod
#     def sign(cls, data, privateKey, encoding='utf8'):
#         '''Hash and sign arbitrary data.

#         @arg {string|Buffer} data - full data
#         @arg {wif|PrivateKey} privateKey
#         @arg {String} [encoding = 'utf8'] - data encoding (if string)

#         @return {Signature}
#         '''
#         # if(typeof data == = 'string') {
#         #     data = Buffer.from(data, encoding)
#         # }
#         # assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
#         # data = hash.sha256(data)
#         # return Signature.signHash(data, privateKey)
#         raise NotImplementedError

#     @classmethod
#     def sign_hash(cls, parameter_list):
#         '''Sign a buffer of exactally 32 bytes in size(sha256(text))

#         @arg {string | Buffer} dataSha256 - 32 byte buffer or string
#         @arg {wif | PrivateKey} privateKey
#         @arg {String} [encoding= 'hex'] - dataSha256 encoding (if string)
#         @return {Signature}
#         '''
#         # Signature.signHash = function(dataSha256, privateKey, encoding='hex') {
#         #     if(typeof dataSha256 === 'string') {
#         #         dataSha256 = Buffer.from(dataSha256, encoding)
#         #     }
#         #     if(dataSha256.length != = 32 | | ! Buffer.isBuffer(dataSha256))
#         #     throw new Error("dataSha256: 32 byte buffer requred")

#         #     privateKey = PrivateKey(privateKey)
#         #     assert(privateKey, 'privateKey required')

#         #     var der, e, ecsignature, i, lenR, lenS, nonce
#         #     i = null
#         #     nonce = 0
#         #     e = BigInteger.fromBuffer(dataSha256)
#         #     while (true) {
#         #         ecsignature = ecdsa.sign(curve, dataSha256, privateKey.d, nonce++)
#         #         der = ecsignature.toDER()
#         #         lenR = der[3]
#         #         lenS = der[5 + lenR]
#         #         if (lenR == = 32 & & lenS == = 32) {
#         #             i = ecdsa.calcPubKeyRecoveryParam(
#         #                 curve, e, ecsignature, privateKey.toPublic().Q)
#         #             i += 4
#         #             // compressed
#         #             i += 27
#         #             // compact // 24 or 27: (forcing odd-y 2nd key candidate)
#         #             break
#         #         }
#         #         if (nonce % 10 == = 0) {
#         #             console.log("WARN: " + nonce +
#         #                         " attempts to find canonical signature")
#         #         }
#         #     }
#         #     return Signature(ecsignature.r, ecsignature.s, i)
#         # }

#         raise NotImplementedError

#     @classmethod
#     def from_buffer(cls, buffer):
#         assert isinstance(buffer, six.binary_type), 'Buffer is required'
#         assert len(buffer) == 65, 'Invalid signature length'
#         return Signature(buffer)

#     # @classmethod
#     # def from_hex(cls, _hex):
#     #     # return Signature.fromBuffer(Buffer.from(hex, "hex"))
#     #     raise NotImplementedError

#     @classmethod
#     def from_string(cls, signature):
#         '''from_string.

#         @arg {string} signature - like SIG_K1_base58signature..
#         @return {Signature} or `null` (invalid)
#         '''
#         try:
#             return cls.from_stringorthrow(signature)
#         except Exception:
#             return None

#     @classmethod
#     def from_stringorthrow(cls, signature):
#         '''from_stringorthrow.

#         @arg {string} signature - like SIG_K1_base58signature..
#         @throws {Error} invalid
#         @return {Signature}
#         '''
#         assert isinstance(signature, six.string_types)
#         match = re.match(r'^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$', signature)
#         assert match and len(match.groups()) == 3, 'Expecting signature like: SIG_K1_base58signature..'  # noqa
#         keyType = match.group(1)
#         keyString = match.group(2)
#         assert keyType == 'K1', 'K1 private key expected'
#         return cls.from_buffer(key_utils.check_decode(keyString, keyType))

#     @classmethod
#     def from_(cls, obj):
#         '''from_.

#         @arg {String | Signature} o - hex string
#         @return {Signature}
#         '''
#         # Signature.from = (o) = > {
#         #     const signature = o ?
#         #     (o.r & & o.s & & o.i) ? o:
#         #         typeof o == = 'string' & & o.length == = 130 ? Signature.fromHex(o):
#         #         typeof o == = 'string' & & o.length != = 130 ? Signature.fromStringOrThrow(o):
#         #     Buffer.isBuffer(o) ? Signature.fromBuffer(o):
#         #     null: o/*null or undefined*/

#         #     if(!signature) {
#         #         throw new TypeError('signature should be a hex string or buffer')
#         #     }
#         #     return signature
#         # }
#         if isinstance(obj, six.string_types):
#             return cls.from_string(obj)
#         elif isinstance(obj, six.binary_type):
#             return cls.from_buffer(obj)
#         else:
#             raise TypeError('from_ obj invaild')
