# -*- coding: utf-8 -*-

import ConfigParser
import cookielib
import logging
import mimetypes
from pprint import pformat
import random
import json
from urlparse import parse_qs, urlparse

import requests
from requests_oauthlib import OAuth1

__version__ = '0.5.0'

REQUEST_TOKEN_URL = 'https://sso.openx.com/api/index/initiate'
ACCESS_TOKEN_URL = 'https://sso.openx.com/api/index/token'
AUTHORIZATION_URL = 'https://sso.openx.com/login/process'
API_PATH_V1 = '/ox/3.0'
API_PATH_V2 = '/ox/4.0'
API_PATH_SSO = '/api'
ACCEPTABLE_PATHS = (API_PATH_V1, API_PATH_V2, API_PATH_SSO)
JSON_PATHS = (API_PATH_V2,)
HTTP_METHOD_OVERRIDES = ['DELETE', 'PUT', 'OPTIONS']


class UnknownAPIFormatError(ValueError):
    """Client is passed an unrecognized API path that it cannot handle."""
    pass


class OAuthException(Exception):
    """Client encountered an Oauth error."""
    pass


class Client(object):
    """Client for making requests to the OX3 API. Maintains
    authentication and points all requests at a domain+path
    combination. Handles request and response data in the form
    of Python dictionaries, translated to and from the JSON and
    query string encoding the API itself uses.

    """

    def __init__(self, domain, realm, consumer_key, consumer_secret,
                 callback_url='oob',
                 scheme='http',
                 request_token_url=REQUEST_TOKEN_URL,
                 access_token_url=ACCESS_TOKEN_URL,
                 authorization_url=AUTHORIZATION_URL,
                 api_path=API_PATH_V1,
                 email=None,
                 password=None,
                 http_proxy=None,
                 https_proxy=None,
                 headers=None,
                 timeout=None):
        """

        domain -- Your UI domain. The API is accessed off this domain.
        realm -- This is no longer used. Just specify None.
        consumer_key -- Your consumer key.
        consumer_secret -- Your consumer secret.
        callback_url -- Callback URL to redirect to on successful authorization.
            We default to 'oob' for headless login.
        request_token -- Only override for debugging.
        access_token -- Only override for debugging.
        authorization_url -- Only override for debugging.
        api_path -- Only override for debugging.
        http_proxy -- Optional proxy to send HTTP requests through.
        headers -- list of headers to send with the request
        timeout -- http request timeout in seconds.
        """

        self.domain = domain
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.callback_url = callback_url
        self.scheme = scheme
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorization_url = authorization_url
        self.api_path = api_path
        self.timeout = timeout

        # Validate API path:
        if api_path not in ACCEPTABLE_PATHS:
            msg = '"{}" is not a recognized API path.'.format(api_path)
            msg += '\nLegal paths include:'
            for i in ACCEPTABLE_PATHS:
                msg += '\n{}'.format(i)
            raise UnknownAPIFormatError(msg)

        # These get cleared after log on attempt.
        self._email = email
        self._password = password

        # You shouldn't need to access the token and session objects directly so we'll keep them private.
        self._token = None
        self._session = requests.Session()
        # set supplied headers and proxies
        if headers:
            self._session.headers.update(headers)
        if http_proxy:
            self._session.proxies.update({'http': http_proxy})
        if https_proxy:
            self._session.proxies.update({'https': https_proxy})

        self.logger = logging.getLogger(__name__)

    def log_request(self, response):
        self.logger.debug('====={0:=<45}'.format('OX3 api call started'))
        self.logger.debug("%s %s" % (response.request.method, response.request.url))
        self.logger.debug('====={0:=<45}'.format('OX3 api call request headers'))
        for k, v in response.request.headers.items():
            self.logger.debug("%s: %s" % (k, v))
        self.logger.debug('====={0:=<45}'.format('OX3 api call request body'))
        self.logger.debug("%s" % response.request.body)
        self.logger.debug('====={0:=<45}'.format('OX3 api call response headers'))
        for k, v in response.headers.items():
            self.logger.debug("%s: %s" % (k, v))
        self.logger.debug('====={0:=<45}'.format('OX3 api call response body'))
        try:
            self.logger.debug(pformat(json.loads(response.content)))
        except ValueError:
            self.logger.debug("%s" % response.content)
        self.logger.debug('====={0:=<45}'.format('OX3 api call finished'))

    def request(self, url, method='GET', headers=None, data=None, sign=False,
                send_json=False):
        """Helper method to make a (optionally OAuth signed) HTTP request."""

        if headers is None:
            headers = {}

        if sign:
            oauth = OAuth1(client_key=self.consumer_key,
                           resource_owner_key=self._token,
                           callback_uri=self.callback_url,
                           signature_type='query')
        else:
            oauth = None
        if send_json:
            response = self._session.request(method, self._resolve_url(url), headers=headers,
                                             json=data, auth=oauth, timeout=self.timeout)
        else:
            response = self._session.request(method, self._resolve_url(url), headers=headers,
                                             data=data, auth=oauth, timeout=self.timeout)
        self.log_request(response)
        response.raise_for_status()
        return response

    def fetch_request_token(self):
        """Helper method to fetch and set request token.

        Returns token string.
        """
        oauth = OAuth1(client_key=self.consumer_key,
                       client_secret=self.consumer_secret,
                       callback_uri=self.callback_url,
                       signature_type='auth_header')
        response = self._session.post(url=self.request_token_url, auth=oauth, timeout=self.timeout)
        self.log_request(response)
        if response.status_code != 200:
            raise OAuthException("OAuth token request failed (%s) %s" % (response.status_code, response.content))
        credentials = parse_qs(response.content)
        self._token = {'key': credentials['oauth_token'][0],
                       'secret': credentials['oauth_token_secret'][0]}
        return self._token

    def authorize_token(self, email=None, password=None):
        """Helper method to authorize."""
        # Give precedence to credentials passed in methods calls over those set
        # in the instance. This allows you to override user creds that may have
        # been loaded from a file.
        if not email:
            email = self._email

        if not password:
            password = self._password

        if not email or not password:
            raise Exception('Missing email or password')

        data = {
            'email': email,
            'password': password,
            'oauth_token': self._token['key']}

        response = self._session.post(url=self.authorization_url, data=data, timeout=self.timeout)
        self.log_request(response)
        if response.status_code != 200:
            raise OAuthException("OAuth login failed (%s) %s" % (response.status_code, response.content))

        # set token verifier
        self._token['verifier'] = parse_qs(response.content)['oauth_verifier'][0]

    def fetch_access_token(self):
        """Helper method to fetch and set access token.

        Returns token string.
        """
        oauth = OAuth1(client_key=self.consumer_key,
                       client_secret=self.consumer_secret,
                       resource_owner_key=self._token['key'],
                       resource_owner_secret=self._token['secret'],
                       verifier=self._token['verifier'],
                       callback_uri=self.callback_url,
                       signature_type='auth_header')
        response = self._session.post(url=self.access_token_url, auth=oauth, timeout=self.timeout)
        self.log_request(response)
        if response.status_code != 200:
            raise OAuthException("OAuth token verification failed (%s) %s" % (response.status_code, response.content))
        self._token = parse_qs(response.content)['oauth_token'][0]
        return self._token

    def validate_session(self):
        """Validate an API session."""

        # We need to store our access token as the openx3_access_token cookie.
        # This cookie will be passed to all future API requests.
        cookie = cookielib.Cookie(
            version=0,
            name='openx3_access_token',
            value=self._token,
            port=None,
            port_specified=False,
            domain=self.domain,
            domain_specified=True,
            domain_initial_dot=False,
            path='/',
            path_specified=True,
            secure=False,
            expires=None,
            discard=False,
            comment=None,
            comment_url=None,
            rest={})
        self._session.cookies.set_cookie(cookie)

        # v2 doesn't need this extra step, just the cookie:
        if self.api_path == API_PATH_V1:
            response = self._session.put(url=self._resolve_url('/a/session/validate'), timeout=self.timeout)
            self.log_request(response)
            return response.content

    def logon(self, email=None, password=None):
        """Returns self after authentication.

        Single call to complete OAuth login process.

        Keyword arguments:
        email -- user email address.
        password -- user password.

        """
        self.fetch_request_token()
        self.authorize_token(email=email, password=password)
        self.fetch_access_token()
        self.validate_session()
        return self

    def logoff(self):
        """Returns self after deleting authenticated session."""
        if self.api_path == API_PATH_V1:
            response = self._session.delete(self._resolve_url('/a/session'), timeout=self.timeout)
        elif self.api_path == API_PATH_V2:
            response = self._session.delete(self._resolve_url('/session'), timeout=self.timeout)
        elif self.api_path == API_PATH_SSO:
            oauth = OAuth1(client_key=self.consumer_key,
                           resource_owner_key=self._token,
                           callback_uri=self.callback_url,
                           signature_type='query')

            response = self._session.delete(url=self.access_token_url, auth=oauth, timeout=self.timeout)
            if response.status_code != 204:
                raise OAuthException("OAuth token deletion failed (%s) %s" % (response.status_code, response.content))
        else:
            raise UnknownAPIFormatError(
                'Unrecognized API path: %s' % self.api_path)
        self.log_request(response)
        return self

    def _resolve_url(self, url):
        """Converts an API path shorthand into a full URL unless
        given a full url already.

        """
        parse_res = urlparse(url)

        # 2.4 returns a tuple instead of ParseResult. Since ParseResult is a
        # subclass or tuple we can access URL components similarly across
        # 2.4 - 2.7. Yay!

        # If there is no scheme specified we create a fully qualified URL.
        if not parse_res[0]:
            url = '%s://%s%s%s' % (self.scheme, self.domain, self.api_path,
                                   parse_res[2])
            if parse_res[4]:
                url = url + '?' + parse_res[4]

        return url

    def _response_value(self, response):
        """ Utility method. Returns decoded json. If the response content cannot be decoded, then
        the content is returned.

        """
        try:
            return response.json()
        except ValueError:
            return response.content

    def get(self, url):
        """Issue a GET request to the given URL or API shorthand

        """
        response = self._session.get(self._resolve_url(url), timeout=self.timeout)
        self.log_request(response)
        response.raise_for_status()
        return self._response_value(response)

    def options(self, url):
        """Send a request with HTTP method OPTIONS to the given
        URL or API shorthand.

        OX3 v2 uses this method for showing help information.

        """
        response = self._session.options(self._resolve_url(url), timeout=self.timeout)
        self.log_request(response)
        response.raise_for_status()
        return self._response_value(response)

    def put(self, url, data=None):
        """Issue a PUT request to url (either a full URL or API
        shorthand) with the data.

        """
        if self.api_path in JSON_PATHS:
            response = self._session.put(self._resolve_url(url), data=json.dumps(data), timeout=self.timeout)
        else:
            response = self._session.put(self._resolve_url(url), data=data, timeout=self.timeout)
        self.log_request(response)
        response.raise_for_status()
        return self._response_value(response)

    def post(self, url, data=None):
        """Issue a POST request to url (either a full URL or API
        shorthand) with the data.

        """
        if self.api_path in JSON_PATHS:
            response = self._session.post(self._resolve_url(url), data=json.dumps(data), timeout=self.timeout)
        else:
            response = self._session.post(self._resolve_url(url), data=data, timeout=self.timeout)
        self.log_request(response)
        response.raise_for_status()
        return self._response_value(response)

    def delete(self, url):
        """Issue a DELETE request to the URL or API shorthand."""
        response = self._session.delete(self._resolve_url(url))
        self.log_request(response)
        response.raise_for_status()
        # Catch no content responses from some delete actions.
        if response.status_code == 204:
            return []
        return self._response_value(response)

    def upload_creative(self, account_id, file_path):
        """Upload a media creative to the account with ID
        account_id from the local file_path.

        """
        # Thanks to nosklo for his answer on SO:
        # http://stackoverflow.com/a/681182
        boundary = '-----------------------------' + str(int(random.random()*1e10))
        parts = []

        # Set account ID part.
        parts.append('--' + boundary)
        parts.append('Content-Disposition: form-data; name="account_id"')
        parts.append('')
        parts.append(str(account_id))

        # Set creative contents part.
        parts.append('--' + boundary)
        parts.append('Content-Disposition: form-data; name="userfile"; filename="%s"' % file_path)
        parts.append('Content-Type: %s' % mimetypes.guess_type(file_path)[0] or 'application/octet-stream')
        parts.append('')
        # TODO: catch errors with opening file.
        parts.append(open(file_path, 'r').read())

        parts.append('--' + boundary + '--')
        parts.append('')

        body = '\r\n'.join(parts)

        # TODO: Catch errors in attempt to upload.
        headers = {'content-type': 'multipart/form-data; boundary=' + boundary}
        if self.api_path == API_PATH_V1:
            url = self._resolve_url('/a/creative/uploadcreative')
        elif self.api_path == API_PATH_V2:
            url = self._resolve_url('/creative/uploadcreative')
        else:
            raise UnknownAPIFormatError(
                'Unrecognized API path: %s' % self.api_path)
        response = self._session.get(url, headers=headers, data=body, timeout=self.timeout)
        self.log_request(response)
        response.raise_for_status()
        return self._response_value(response)


def client_from_file(file_path='.ox3rc', env=None):
    """Return an instance of ox3apiclient.Client with data from file_path.

    Keyword arguments:
    file_path -- the file to load. Default is '.ox3rc' form current dir.
    env -- the env section to load. Default will be first env section.

    """
    cp = ConfigParser.RawConfigParser()
    cp.read(file_path)

    # Load default env if no env is specified. The default env is just the first
    # env listed.
    if not env:
        env = [e for e in cp.get('ox3apiclient', 'envs').split('\n') if e][0]

    # Required parameters for a ox3apiclient.Client instance.
    required_params = [
        'domain',
        'consumer_key',
        'consumer_secret']

    client_params = {}

    # Load required parameters.
    try:
        for param in required_params:
            client_params[param] = cp.get(env, param)
    except ConfigParser.NoOptionError:
        err_msg = "Missing required option: '%s'" % param
        raise Exception(err_msg)

    client = Client(
        domain=client_params['domain'],
        realm=None,
        consumer_key=client_params['consumer_key'],
        consumer_secret=client_params['consumer_secret'])

    # Load optional parameters.
    optional_params = [
        'callback_url',
        'scheme',
        'request_token_url',
        'access_token_url',
        'authorization_url',
        'api_path',
        'email',
        'password',
        'timeout']

    for param in optional_params:
        try:
            prop = param

            # Prefix private properties with '_'.
            if prop in ['email', 'password']:
                prop = '_%s' % prop

            client.__dict__[prop] = cp.get(env, param)

        except ConfigParser.NoOptionError:
            pass

    return client

# The exposed API has moved to using Client instead of OX3APIClient, but create
# a temporary alias for backwards compatibility.
OX3APIClient = Client
