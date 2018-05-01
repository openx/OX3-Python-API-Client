#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
from os.path import dirname, join
import os
import re

def read_file(name):
    filename = join(dirname(__file__), name)
    with open(filename) as fp:
        return fp.read()

file_path = join(dirname(__file__), 'ox3apiclient', '__init__.py')
version = re.search("__version__\s*=\s*['\"](.+)['\"]",
                    open(file_path, 'r').read()).groups()[0]

setup(name='ox3apiclient',
    version=version,
    author='OpenX API Team',
    author_email='api@openx.com',
    url='https://github.com/openx/OX3-Python-API-Client',
    license='BSD',
    platforms=['POSIX'],
    description='Client to connect to the OpenX Enterprise API.',
    long_description=read_file('README.md'),
    packages=find_packages(),
    zip_safe=True,
    install_requires=['six','requests_oauthlib'],
    classifiers=[
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    test_suite='nose.collector',
    tests_require=[
        'nose',
        'mock; python_version < "3.3"'
    ]
)
