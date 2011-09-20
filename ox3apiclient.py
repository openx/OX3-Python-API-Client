#!/usr/bin/env python

import oauth2 as oauth
import urllib
import urllib2
import urlparse

REQUEST_TOKEN_URL = 'https://sso.openx.com/api/index/initiate'
ACCESS_TOKEN_URL = 'https://sso.openx.com/api/index/token'
AUTHORIZATION_URL = 'https://sso.openx.com/login/process'
API_PATH = '/ox/3.0/a'
HTTP_METHOD_OVERRIDES = ['DELETE', 'PUT']

class OX3APIClient(object):
    
    def __init__(self, domain, realm, consumer_key, consumer_secret,
                    callback_url='oob',
                    request_token_url=REQUEST_TOKEN_URL,
                    access_token_url=ACCESS_TOKEN_URL,
                    authorization_url=AUTHORIZATION_URL,
                    api_path=API_PATH):
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
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorization_url = authorization_url
        self.callback_url = callback_url
        self.api_path = api_path
        
        # You shouldn't need to access the oauth2 consumer and token objects
        # directly so we'll keep them "private".
        self._consumer = oauth.Consumer(self.consumer_key, self.consumer_secret)
        self._token = oauth.Token('', '')
    
    def _sign_request(self, req):
        """Utility method to sign a request."""
        parameters = {'oauth_callback': self.callback_url}
        headers = req.headers
        data = req.data
        
        # Add any (POST) data to the parameters to be signed in the OAuth
        # request as well as store 'stringified' copy for the request's body.
        if data:
            parameters.update(data)
            data = urllib.urlencode(data)
        
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
        
        # Update or original requests headers to include the OAuth Authorization
        # header and return it.
        req.headers.update(oauth_req.to_header(realm=self.realm))
        return urllib2.Request(req.get_full_url(), headers=req.headers, data=data)
    
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
        
        return urllib2.urlopen(req)
    
    def fetch_request_token(self):
        """Helper method to fetch and set request token.
        
        Returns token string.
        """
        res = self.request(url=REQUEST_TOKEN_URL, method='POST', sign=True)
        token = urlparse.parse_qs(res.read())
        self._token = oauth.Token(token['oauth_token'][0], token['oauth_token_secret'][0])
        return self._token
    
