# -*- coding: utf-8 -*-
import ox3apiclient
import unittest
from mock import Mock, patch
import os


class TestClient(unittest.TestCase):
    ex_resp = Mock()
    ex_resp.request.headers = {'rheader1': 'rvalue1',
                               'rheader2': 'rvalue2'}
    ex_resp.headers = {'header1': 'value1',
                       'header2': 'value2'}
    ex_resp.text = 'oauth_token=key&oauth_token_secret=secret&oauth_callback_confirmed=true'
    ex_resp.json.return_value = {'key1': 'value1',
                                 'key2': 'value2',
                                 'key3': 'value3'}
    # Change this depending on needs, default is 200
    ex_resp.status_code = 200

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

        with patch('ox3apiclient.requests.Session') as\
        self.mock_requests_session,\
        patch('ox3apiclient.Client.log_request') as\
        self.mock_client_log_request:
          self.mock_requests_session.return_value.get.return_value = self.ex_resp
          self.mock_requests_session.return_value.post.return_value = self.ex_resp
          self.mock_requests_session.return_value.put.return_value = self.ex_resp
          self.mock_requests_session.return_value.options.return_value = self.ex_resp
          self.mock_requests_session.return_value.delete.return_value = self.ex_resp

          self.mock_client_log_request.return_value = None
          self.client = ox3apiclient.Client(
              email=self.email,
              password=self.password,
              domain=self.domain,
              realm=self.realm,
              consumer_key=self.consumer_key,
              consumer_secret=self.consumer_secret,
              request_token_url=self.request_token_url,
              access_token_url=self.access_token_url,
              authorization_url=self.authorization_url)

    def test_init(self):
        pass

    def test_log_request(self):
        pass

    def test_request(self):
        pass

    def test_fetch_request_token(self):
        # Authorized Case
        ret_val = self.client.fetch_request_token()
        self.assertTrue(isinstance(ret_val, dict))
        self.assertEqual(
            (ret_val['secret'], ret_val['key']), ('secret', 'key'))
        # UnAuthorized Case
        self.ex_resp.status_code = 401
        with self.assertRaises(ox3apiclient.OAuthException):
            self.client.fetch_request_token()

    @patch('ox3apiclient.Client.fetch_request_token')
    @patch('ox3apiclient.Client.log_request')
    def test_authorize_token(self,
                             mock_client_log_request,
                             mock_fetch_request_token):
        # mock the post response, and do some setup
        r = Mock()
        r.text = 'oauth_verifier=verifier'
        self.mock_requests_session.return_value.post.return_value = r
        mock_client_log_request.return_value = None
        mock_fetch_request_token.return_value = {'key': 'key',
                                                 'secret': 'secret'}
        self.client._token = {'key': 'key',
                              'secret': 'secret'}

        # UnAuthorized Case
        r.status_code = 401
        with self.assertRaises(ox3apiclient.OAuthException):
            self.client.authorize_token()
        # Authorized Case
        r.status_code = 200
        self.client.authorize_token()
        self.assertEqual(self.client._token['verifier'], 'verifier')

    @patch('requests_oauthlib.OAuth1')
    @patch('ox3apiclient.Client.log_request')
    def test_fetch_access_token(self, mock_client_log_request, mock_oauth1):
        # mock the OAuth1 and session post response
        mock_oauth1.return_value = 'oauth'
        r = Mock()
        r.text = 'oauth_token=key'
        self.mock_requests_session.return_value.post.return_value = r
        self.client._token = {'key': 'key',
                              'secret': 'secret',
                              'verifier': 'verifier'}

        # UnAuthorized Case
        r.status_code = 401
        with self.assertRaises(ox3apiclient.OAuthException):
            self.client.fetch_access_token()
        # Authorized Case
        r.status_code = 200
        self.assertEqual(self.client.fetch_access_token(), 'key')

    def test_validate_session(self):
        ret_val = self.client.validate_session()
        self.assertEqual(ret_val,
                         'oauth_token=key&'
                         'oauth_token_secret=secret&'
                         'oauth_callback_confirmed=true')

    def test_logon(self):
        with patch('ox3apiclient.Client.fetch_request_token') as\
        mock_fetch_request_token,\
        patch('ox3apiclient.Client.authorize_token') as mock_authorize_token,\
        patch('ox3apiclient.Client.fetch_access_token') as\
        mock_fetch_access_token,\
        patch('ox3apiclient.Client.validate_session') as mock_validate_session:
            mock_fetch_request_token.return_value = None
            mock_authorize_token.return_value = None
            mock_fetch_access_token.return_value = None
            mock_validate_session.return_value = None
            ret_val = self.client.logon()
            self.assertTrue(isinstance(ret_val, ox3apiclient.Client))

    def test_logoff(self):
        ret_val = self.client.logoff()
        self.assertTrue(isinstance(ret_val, ox3apiclient.Client))

    # def test_resolve_url(self):
    #     pass

    def test_get(self):
        ret_val = self.client.get(self.url)
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    def test_options(self):
        ret_val = self.client.options(self.url)
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    def test_put(self):
        ret_val = self.client.put(self.url, data={'k': 'v'})
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    def test_post(self):
        ret_val = self.client.post(self.url, data={'k': 'v'})
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

    @patch('ox3apiclient.requests.Session.delete')
    @patch('ox3apiclient.Client.log_request')
    def test_delete(self, mock_client_log_request, mock_requests_session_delete):
        mock_client_log_request.return_value = None
        r = Mock()
        r.status_code = 204
        mock_requests_session_delete.return_value = r
        ret_val = self.client.delete(self.url)
        self.assertEqual(ret_val, [])

        r.status_code = 200
        # r.content = {'key': 'value'}
        # ret_val = self.client.delete('https://example.com')
        # mock_requests_delete.return_value.json.side_effect = AttributeError
        # self.assertEqual(ret_val, {'key': 'value'})

        r.json.return_value = {'key': 'value'}
        ret_val = self.client.delete(self.url)
        self.assertEqual(ret_val, {'key': 'value'})

    def test_upload_creative(self):
        file_path = os.path.join(os.path.dirname(__file__), 'ox3rctest')
        ret_val = self.client.upload_creative('123456789', file_path)
        self.assertEqual(ret_val, {'key1': 'value1',
                                   'key2': 'value2',
                                   'key3': 'value3'})

if __name__ == '__main__':
    # run this using python -m unittes -v tests from the root dir
    unittest.main()
