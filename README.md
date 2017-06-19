# ox3apiclient

A small class to help connect to the OpenX Enterprise API. As of version 0.5.0 it  uses
[requests_oauthlib](https://github.com/requests/requests-oauthlib) instead of oauth2.

It currently supports Python 2.6 - 3.5.

As of version 0.4.0, ox3apiclient supports API v2. If your instance is v2,
set the api_path option to "/ox/4.0".

As of version 0.5.0 the client.request method returns a requests.Response object instead of
urllib2.Response and throws a requests.exceptions.HTTPError instead of urllib2.HTTPError.
In addition debugging is now available via the standard python logging facility.

See the [requests documentation](http://docs.python-requests.org/en/latest/) for details.

Basic usage with debugging enabled:

````python
import ox3apiclient
import logging

ox = ox3apiclient.client_from_file().logon()

ox.logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ox.logger.addHandler(ch)

accounts = ox.get('/account')

order = {
    'status': 'Active',
    'name': 'OX3APIClient Object Creation Test',
    'account_uid': accounts['objects'][0]['account_uid'],
    'start_date': '2016-06-01 00:00:00'}

new_order = ox.post('/order', data=order)

ox.delete('/order/%s' % new_order['uid'])

ox.logoff()
````


## Installation

From Pypi

The last released version (from the master branch) is available at [PyPi](http://pypi.python.org/pypi)
````
$ pip install ox3apiclient
````


From Github:

Just clone our git repo:

````
$ git clone https://github.com/openx/OX3-Python-API-Client.git
````

Install the downloaded library:
````
python setup.py install
````
this will install the current dependencies.

## Authentication

The recommended method of authentication is to use `ox3apiclient.client_from_file`.
By default this will look for a file named `.ox3rc` in the current current
directory, but this can be overwritten by specifying a `file_path` parameter. The
file should be in the following format:

````
[ox3apiclient]
envs=
    dev
    prod

[dev]
email: you@example.com
password: password123
domain: dev.uidomain.com
realm: dev.uidomain_realm
consumer_key: 1fc5c9ae...
consumer_secret: 7c664d68...
authorization_url: http://custom_sso.uidomain.com/api/index/initiate

[prod]
email: you@example.com
password: password123
domain: uidomain.com
realm: uidomain_realm
consumer_key: 1fc5c9ae...
consumer_secret: 7c664d68...
````

`ox3apiclient.client_from_file` will use the first `env` by default but this can
be overwritten by setting the `env` parameter. If your email and password are set
in `.ox3rc` you can simply chain a call to `logon()`.

Alternatively you can set everything in your code.
````python
email = 'you@example.com'
password = 'password123'
domain = 'uidomain.com'
realm = 'uidomain_realm'
consumer_key = '1fc5c9ae...'
consumer_secret = '7c664d68...'

ox = ox3apiclient.Client(
    email=email,
    password=password,
    domain=domain,
    realm=realm,
    consumer_key=consumer_key,
    consumer_secret=consumer_secret)

ox.logon(email, password)
````

    # To run these tests. Install nose (pip install nose)
    # and run nosetests -sxv tests/  from the root dir

## Tests

Install nose

````bash
pip install nose
```` 
 
 and run the following command line from the root:

````bash
nosetests -sxv tests/
````