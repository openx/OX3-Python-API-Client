# ox3apiclient

A small class to help connect to the OpenX Enterprise API. While it uses [oauth2](https://github.com/simplegeo/python-oauth2),
it does not use [httplib2](http://code.google.com/p/httplib2/) as the transport due to issues with headers created by
httplib2. Instead it uses urllib2 as the HTTP transport.

It currently supports Python 2.4 - 2.7, with 3.x support comming in the future.

As of version 0.4.0, ox3apiclient supports API v2. If your instance is v2,
set the api_path option to "/ox/4.0".

Basic usage:

````python
import ox3apiclient

ox = ox3apiclient.client_from_file().logon()

account_ids = ox.get('/a/account')

order = {
    'status': 'Active',
    'name': 'OX3APIClient Object Creation Test',
    'account_id': account_ids[0],
    'start_date': '2012-08-22 00:00:00'}

new_order = ox.post('/a/order', data=order)

ox.delete('/a/order/%s' % new_order['id'])

ox.logoff()
````


## Installation

Install from [PyPi](http://pypi.python.org/pypi) with [pip](http://www.pip-installer.org/en/latest/index.html)

````
$ pip install ox3apiclient
````
This should install the [oauth2](https://github.com/simplegeo/python-oauth2) dependency, but you can manually install if needed.
````
$ pip install oauth2
````

Note that Python 2.4 and 2.5 support requires simplejson. You will need
simplejson 2.1.0 specifically for Python 2.4. You can install this version with:
````
$ pip install simplejson==2.1.0
````


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