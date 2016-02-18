#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-

from distutils.core import setup
from os.path import dirname, join
import re

file_path = join(dirname(__file__), 'ox3apiclient', '__init__.py')
version = re.search("__version__\s*=\s*['\"](.+)['\"]",
    open(file_path, 'r').read()).groups()[0]

setup(name='ox3apiclient',
    version=version,
    author='Tony Edwards',
    author_email='tnydwrds@gmail.com',
    url='https://github.com/tnydwrds/OX3-Python-API-Client',
    description='Client to connect to OpenX Enterprise API.',
    long_description='Client to connect to OpenX Enterprise API.',
    packages=['ox3apiclient'],
    install_requires=['oauth2'],
    classifiers=[
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules'])
