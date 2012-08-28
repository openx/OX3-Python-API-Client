# -*- coding: utf-8 -*-

import os.path
import unittest

import ox3apiclient

class ClientFromFileTestCase(unittest.TestCase):

    def test_returns_client(self):
        file_path = os.path.join(os.path.dirname(__file__), 'ox3rctest')
        ox = ox3apiclient.client_from_file(file_path=file_path)
        self.assertTrue(isinstance(ox, ox3apiclient.Client))

    def test_loads_default_env(self):
        file_path = os.path.join(os.path.dirname(__file__), 'ox3rctest')
        ox = ox3apiclient.client_from_file(file_path=file_path)

        test_values = [
            'domain',
            'realm',
            'consumer_secret',
            'consumer_key']

        loaded_values = [
            ox.domain,
            ox.realm,
            ox.consumer_key,
            ox.consumer_secret]

        test_values.sort()
        loaded_values.sort()
        self.assertEqual(loaded_values, test_values)

    def test_loads_alternate_env(self):
        file_path = os.path.join(os.path.dirname(__file__), 'ox3rctest')
        ox = ox3apiclient.client_from_file(file_path=file_path, env='dev')

        test_values = [
            'domain_dev',
            'realm_dev',
            'consumer_secret_dev',
            'consumer_key_dev']

        loaded_values = [
            ox.domain,
            ox.realm,
            ox.consumer_key,
            ox.consumer_secret]

        test_values.sort()
        loaded_values.sort()
        self.assertEqual(loaded_values, test_values)

    def test_missing_required_option_raises_error(self):
        file_path = os.path.join(os.path.dirname(__file__), 'ox3rctest')
        self.assertRaises(
            Exception,
            ox3apiclient.client_from_file,
            file_path,
            'missing-required-option')
