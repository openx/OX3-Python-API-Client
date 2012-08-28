#OX3-Python-API-Client - Python class to access OpenX Enterprise API
OX3-Python-API-Client is a small class to help demonstrate how to connect to the OpenX Enterprise API. It depends on the [simplegeo/python-oauth2](https://github.com/simplegeo/python-oauth2) module.

It currently supports Python 2.7 and will be updated to support Python 3.x.

````python
import datetime
import ox3apiclient

# User credentials
email_address = ''
password = ''

# OAuth credentials. These will be supplied by your Account Manager or Support.
domain = ''
realm = ''
consumer_key = ''
consumer_secret = ''


ox = ox3apiclient.OX3APIClient(domain, realm, consumer_key, consumer_secret)

# Step 1. Fetch temporary request token.
ox.fetch_request_token()

# Step 2. Log in to SSO server and authorize token.
ox.authorize_token(email_address, password)

# Step 3. Swap temporary request token for permanent access token.
# If you need to store the access token yourself you can do so with something
# similar to:
#   token_str = ox.fetch_access_token()
#   access_token = urlparse.parse_qs(token_str)['oauth_token'][0]
ox.fetch_access_token()

# Step 4. Validate your access token.
# You'll more than likely want to call the validate_session method, but you can
# manually validate your access token if needed. You will be resonpsible for
# passing the requisite openx3_access_token for all successive API requests. A
# method might look like the following:
#   token_str = ox.fetch_access_token()
#   access_token = urlparse.parse_qs(token_str)['oauth_token'][0]
#   cookie_header = {'Cookie': 'openx3_access_token=' + access_token}
#   ox.request(url='http://youruidomain.com/ox/3.0/a/session/validate',
#       method='PUT',
#       headers=cookie_header)
ox.validate_session()


# Now that we have connected let's try making a few API requests.
# Print out account names. We use overload=medium to get more than just a
# listing of ids.
accounts = ox.get('/a/account?overload=medium')
for account in accounts:
    msg = 'Account ID: %s, Account Name: %s'
    print(msg % (account['id'], account['name']))

# We won't test object creation with accounts because they can't be deleted
# currently. Instead, we will create an order under an advertiser account.
account_id = 0 #<= Replace with a valid advertiser account id for your instance.

if account_id:

    # You can check to see what fields are required for the create action.
    # required_fields = ox.get('/a/order/requiredFields?action=create')
    # print(required_fields) #=> {u'status': u'string', u'name': u'string', u'account_id': u'int', u'start_date': u'datetime'}

    # OX3APIClient methods accept Python dicts for data parameters, so we can
    # define an order as a normal dict.
    order = {
        'status': 'Active',
        'name': 'OX3APIClient Object Creation Test',
        'account_id': account_id,
        'start_date': datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S'),
    }

    new_order = ox.post('/a/order', data=order)
    # print(order) #=> {u'id': 12345}
    print('Created order id %s' % new_order['id'])

    # Let's get all the details on the order we just created.
    existing_order = ox.get('/a/order/%s' % new_order['id'])
    print(existing_order)

# Log out.
ox.delete('/a/session')
````
Test
