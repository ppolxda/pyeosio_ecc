# -*- coding: utf-8 -*-
u"""
@create: 2017-03-09 15:15:05.

@author: asdfsdf

@desc: setup
"""
import os
import sys
import codecs
# import shutil
from setuptools import setup, find_packages, findall


# print(find_packages())
# print(findall('pypplugins/_templates'))
# print(findall('pypplugins/_proto'))
# print(os.path.join(sys.prefix, 'MyApp', 'CBV'))
# is_py2 = sys.version_info.major == 2
# is_windows = sys.platform.startswith('win')


setup(
    name="pyeosio_ecc",
    version="0.0.2",
    install_requires=[
        'six',
        'base58',
        'ecdsa'
    ],
    packages=find_packages('.'),
    python_requires=">=2.7,>=3.0.*",
    author="ppolxda",
    author_email="sa@sa.com",
    description="pyeosio_ecc",
    license="pyeosio_ecc",
    keywords="pyeosio_ecc",
    # url="http://example.com/HelloWorld/",
)
