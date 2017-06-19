# -*- coding: utf-8 -*-
import ox3apiclient
import unittest
from mock import Mock, patch
import os


class TestClient(unittest.TestCase):

    def setUp(self):
        self.email = 'you@example.com'
        self.password = 'password123'
        self.domain = 'uidomain.com'
        self.realm = 'uidomain_realm'
        self.consumer_key = '1fc5c9ae...'
        self.consumer_secret = '7c664d68...'
        self.request_token_url = 'https://ex-sso.openx.org/api/index/initiate'
        self.access_token_url = 'https://ex-sso.openx.org/api/index/token'
        self.authorization_url = 'https://ex-sso.openx.org/api/login/process'
        self.api_path_v1 = '/ox/3.0'
        self.api_path_v2 = '/ox/4.0'
        self.url = 'https://www.example.com'

    def _get_client(self, get_return=None, put_return=None, post_return=None, options_return=None, delete_return=None):
        ex_resp = self._build_mock_response()

        with patch('ox3apiclient.requests.Session') as mock_requests_session:
            with patch('ox3apiclient.Client.log_request') as mock_client_log_request:
                mock_requests_session.return_value.get.return_value = get_return or ex_resp
                mock_requests_session.return_value.post.return_value = post_return or ex_resp
                mock_requests_session.return_value.put.return_value = put_return or ex_resp
                mock_requests_session.return_value.options.return_value = options_return or ex_resp
                mock_requests_session.return_value.delete.return_value = delete_return or ex_resp

                mock_client_log_request.return_value = None
                return ox3apiclient.Client(
                    email=self.email,
                    password=self.password,
                    domain=self.domain,
                    realm=self.realm,
                    consumer_key=self.consumer_key,
                    consumer_secret=self.consumer_secret,
                    request_token_url=self.request_token_url,
                    access_token_url=self.access_token_url,
                    authorization_url=self.authorization_url)

    def _build_mock_response(self):
        resp = Mock()
        resp.request.headers = {'rheader1': 'rvalue1',
                                'rheader2': 'rvalue2'}
        resp.headers = {'header1': 'value1',
                        'header2': 'value2'}
        resp.text = 'oauth_token=key&oauth_token_secret=secret&oauth_callback_confirmed=true'
        resp.json.return_value = {'key1': 'value1',
                                  'key2': 'value2',
                                  'key3': 'value3'}

        resp.status_code = 200
        return resp

    def test_fetch_request_token(self):
        # Authorized Case
        resp = self._build_mock_response()
        client = self._get_client(post_return=resp)

        ret_val = client.fetch_request_token()
        self.assertTrue(isinstance(ret_val, dict))
        self.assertEqual((ret_val['secret'], ret_val['key']), ('secret', 'key'))

        # Unauthorized Case
        resp.status_code = 401
        with self.assertRaises(ox3apiclient.OAuthException):
            client.fetch_request_token()

    def test_authorize_token(self):
        # mock the post response, and do some setup
        r = self._build_mock_response()
        r.text = 'oauth_verifier=verifier'
        r.return_value = {'key': 'key', 'secret': 'secret'}
        client = self._get_client(post_return=r)
        client._token = {'key': 'key', 'secret': 'secret'}

        # Unauthorized Case
        r.status_code = 401
        with self.assertRaises(ox3apiclient.OAuthException):
            client.authorize_token()

        # Authorized Case
        r.status_code = 200
        client.authorize_token()
        self.assertEqual(client._token['verifier'], 'verifier')

    def test_fetch_access_token(self):
        # mock the OAuth1 and session post response
        r = self._build_mock_response()
        r.text = 'oauth_token=key'
        r.return_value = 'oauth_token=key'
        client = self._get_client(post_return=r)
        client._token = {'key': 'key',
                         'secret': 'secret',
                         'verifier': 'verifier'}

        # Unauthorized Case
        r.status_code = 401
        with self.assertRaises(ox3apiclient.OAuthException):
            client.fetch_access_token()

        # Authorized Case
        r.status_code = 200
        self.assertEqual(client.fetch_access_token(), 'key')

    def test_validate_session(self):
        client = self._get_client()

        ret_val = client.validate_session()
        self.assertEqual(ret_val,
                         'oauth_token=key&'
                         'oauth_token_secret=secret&'
                         'oauth_callback_confirmed=true')

    def test_logon(self):
        with patch('ox3apiclient.Client.fetch_request_token') as mock_fetch_request_token:
            with patch('ox3apiclient.Client.authorize_token') as mock_authorize_token:
                with patch('ox3apiclient.Client.fetch_access_token') as mock_fetch_access_token:
                    with patch('ox3apiclient.Client.validate_session') as mock_validate_session:
                        client = self._get_client()
                        mock_fetch_request_token.return_value = None
                        mock_authorize_token.return_value = None
                        mock_fetch_access_token.return_value = None
                        mock_validate_session.return_value = None
                        ret_val = client.logon()
                        self.assertTrue(isinstance(ret_val, ox3apiclient.Client))

    def test_logoff(self):
        client = self._get_client()
        ret_val = client.logoff()
        self.assertTrue(isinstance(ret_val, ox3apiclient.Client))

    def test_get(self):
        client = self._get_client()
        ret_val = client.get(self.url)
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    def test_options(self):
        client = self._get_client()
        ret_val = client.options(self.url)
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    def test_put(self):
        client = self._get_client()
        ret_val = client.put(self.url, data={'k': 'v'})
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    def test_post(self):
        client = self._get_client()
        ret_val = client.post(self.url, data={'k': 'v'})
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    def test_delete(self):
        r = self._build_mock_response()
        r.status_code = 204
        client = self._get_client(delete_return=r)
        ret_val = client.delete('https://example.com')
        self.assertEqual(ret_val, [])

        r.status_code = 200
        r.json.return_value = {'key': 'value'}
        ret_val = client.delete('https://example.com')
        self.assertEqual(ret_val, {'key': 'value'})

    def test_upload_creative(self):
        file_path = os.path.join(os.path.dirname(__file__), 'ox3rctest')
        client = self._get_client()
        ret_val = client.upload_creative('123456789', file_path)
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})
