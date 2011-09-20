#!/usr/bin/env python

import oauth2 as oauth
import urllib2

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
    
    def request(self, url, method='GET', headers={}, data=None, sign=False):
        """Helper method to make a HTTP request."""
        
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
        
        return urllib2.urlopen(req)

