# -*- coding: utf-8 -*-

import ConfigParser
import cookielib
import json
import oauth2 as oauth
import urllib
import urllib2
import urlparse

__version__ = '0.1.0'

REQUEST_TOKEN_URL = 'https://sso.openx.com/api/index/initiate'
ACCESS_TOKEN_URL = 'https://sso.openx.com/api/index/token'
AUTHORIZATION_URL = 'https://sso.openx.com/login/process'
API_PATH = '/ox/3.0'
HTTP_METHOD_OVERRIDES = ['DELETE', 'PUT']

class Client(object):

    def __init__(self, domain, realm, consumer_key, consumer_secret,
                    callback_url='oob',
                    scheme='http',
                    request_token_url=REQUEST_TOKEN_URL,
                    access_token_url=ACCESS_TOKEN_URL,
                    authorization_url=AUTHORIZATION_URL,
                    api_path=API_PATH,
                    email=None,
                    password=None):
        """

        domain -- Your UI domain. The API is accessed off this domain.
        realm -- Your sso realm. While not necessary for all OAuth
            implementations, it is a requirement for OpenX Enterprise
        consumer_key -- Your consumer key.
        consumer_secret -- Your consumer secret.
        callback_url -- Callback URL to redirect to on successful authorization.
            We default to 'oob' for headless login.
        request_token -- Only override for debugging.
        access_token -- Only override for debugging.
        authorization_url -- Only override for debugging.
        api_path -- Only override for debugging.
        """
        self.domain = domain
        self.realm = realm
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.callback_url = callback_url
        self.scheme=scheme
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorization_url = authorization_url
        self.api_path = api_path

        # These get cleared after log on attempt.
        self._email = email
        self._password = password

        # You shouldn't need to access the oauth2 consumer and token objects
        # directly so we'll keep them "private".
        self._consumer = oauth.Consumer(self.consumer_key, self.consumer_secret)
        self._token = None

        # Similarly you probably won't need to access the cookie jar directly,
        # so it is private as well.
        self._cookie_jar = cookielib.LWPCookieJar()
        opener = \
            urllib2.build_opener(urllib2.HTTPCookieProcessor(self._cookie_jar))

        urllib2.install_opener(opener)

    def _sign_request(self, req):
        """Utility method to sign a request."""
        parameters = {'oauth_callback': self.callback_url}
        headers = req.headers
        data = req.data

        # Add any (POST) data to the parameters to be signed in the OAuth
        # request.
        if data:
            parameters.update(data)

        # Create a temporary oauth2 Request object and sign it so we can steal
        # the Authorization header.
        oauth_req = oauth.Request.from_consumer_and_token(
            consumer=self._consumer,
            token=self._token,
            http_method=req.get_method(),
            http_url=req.get_full_url(),
            parameters=parameters,
            is_form_encoded=True)

        oauth_req.sign_request(
            oauth.SignatureMethod_HMAC_SHA1(),
            self._consumer,
            self._token)

        # Update our original requests headers to include the OAuth Authorization
        # header and return it.
        req.headers.update(oauth_req.to_header(realm=self.realm))
        return \
            urllib2.Request(req.get_full_url(), headers=req.headers, data=data)

    def request(self, url, method='GET', headers={}, data=None, sign=False):
        """Helper method to make a (optionally OAuth signed) HTTP request."""

        # Since we are using a urllib2.Request object we need to assign a value
        # other than None to "data" in order to make the request a POST request,
        # even if there is no data to post.
        if method == 'POST':
            data = data if data else ''

        req = urllib2.Request(url, headers=headers, data=data)

        # We need to set the request's get_method function to return a HTTP
        # method for any values other than GET or POST.
        if method in HTTP_METHOD_OVERRIDES:
            req.get_method = lambda: method

        if sign:
            req = self._sign_request(req)

        # Stringify data.
        if data:
            req.add_data(urllib.urlencode(req.get_data()))

        return urllib2.urlopen(req)

    def fetch_request_token(self):
        """Helper method to fetch and set request token.

        Returns token string.
        """
        res = self.request(url=self.request_token_url, method='POST', sign=True)
        self._token = oauth.Token.from_string(res.read())
        return self._token

    def authorize_token(self, email=None, password=None):
        """Helper method to authorize."""
        # Give precedence to credentials passed in methods calls over those set
        # in the instance. This allows you to override user creds that may have
        # been loaded from a file.
        email = email if email else self._email
        password = password if password else self._password

        if not email or not password:
            self._email = self._password = None
            raise Exception('Missing email or password')

        data = {
            'email': email,
            'password': password,
            'oauth_token': self._token.key}

        res = self.request(
                url=self.authorization_url,
                method='POST',
                data=data,
                sign=True)

        # Clear user credentials.
        self._email = self._password = None

        verifier = urlparse.parse_qs(res.read())['oauth_verifier'][0]
        self._token.set_verifier(verifier)

    def fetch_access_token(self):
        """Helper method to fetch and set access token.

        Returns token string.
        """
        res = self.request(url=self.access_token_url, method='POST', sign=True)
        self._token = oauth.Token.from_string(res.read())
        return self._token

    def validate_session(self):
        """Validate an API session."""

        # We need to store our access token as the openx3_access_token cookie.
        # This cookie will be passed to all future API requests.
        cookie = cookielib.Cookie(
            version=0,
            name='openx3_access_token',
            value=self._token.key,
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

        self._cookie_jar.set_cookie(cookie)

        url = '%s://%s%s/a/session/validate' % (self.scheme,
                                                self.domain,
                                                self.api_path)

        res = self.request(url=url, method='PUT')
        return res.read()

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
        self.delete('/a/session')
        return self

    def _resolve_url(self, url):
        """"""
        parse_res = urlparse.urlparse(url)
        if not parse_res.scheme:
            url ='%s://%s%s%s' % (self.scheme, self.domain, self.api_path,
                                    parse_res.path)
            url = url + '?' + parse_res.query if parse_res.query else url

        return url

    def get(self, url):
        """"""
        res = self.request(self._resolve_url(url), method='GET')
        return json.loads(res.read())

    def post(self, url, data=None):
        """"""
        res = self.request(self._resolve_url(url), method='POST', data=data)
        return json.loads(res.read())

    def delete(self, url):
        """"""
        res = self.request(self._resolve_url(url), method='DELETE')
        return json.loads(res.read())


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
    env_ids = [e for e in cp.get('ox3apiclient', 'envs').split('\n') if e]
    env = env if env else env_ids[0]

    # Required parameters for a ox3apiclient.Client instance.
    required_params = [
        'domain',
        'realm',
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
        realm=client_params['realm'],
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
        'password']

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
