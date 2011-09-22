import datetime
import ox3apiclient
import urllib

usr = ''
pwd = ''

domain = ''
realm = ''
consumer_key = ''
consumer_secret = ''

ox = ox3apiclient.OX3APIClient(domain, realm, consumer_key, consumer_secret)

# Step 1. Fetch temporary request token.
ox.fetch_request_token()

# Step 2. Log in to SSO server and authorize token.
ox.authorize_token(usr, pwd)

# Step 3. Swap temporary request token for permanent access token.
ox.fetch_access_token()

# Step 4. Validate your access token.
# You'll more than likely want to call the validate_session method, but you may
# need to grab the access token directly for some reason (maybe this is a
# server-side proxy between a custom site and the API?). Regardless, you can get
# the access token when you call fetch_access_token:
#
#   token_str = ox.fetch_access_token()
#   access_token = urlparse.parse_qs(token_str)['oauth_token'][0]
#
#
# Alternatively, after calling fetch_access_token you can grab it off the
# "private" _token property like:
#
#   access_token = ox._token.key
#
# 
ox.validate_session()

# Or manually validate your access token (but you will be resonpsible for
# passing the requisite openx3_access_token for all successive API requests.
#   token_str = ox.fetch_access_token()
#   access_token = urlparse.parse_qs(token_str)['oauth_token'][0]
#   cookie_header = {'Cookie': 'openx3_access_token=' + access_token}
#   ox.request(url='http://youruidomain.com/ox/3.0/a/session/validate',
#       method='PUT',
#       headers=cookie_header)


# Print out account names. We use overload=medium to get more than just a
# listing of ids.
accounts = ox.get('/a/account?overload=medium')
for account in accounts:
    msg = '\tAccount ID: %s, Account Name: %s'
    print(msg % (account['id'], account['name']))

# We won't test object creation with accounts because they can't be deleted
# currently.
account_id = 0 #<= Replace with a valid advertiser account id for your instance.
if account_id:
    # required_fields = ox.get('/a/order/requiredFields')
    # print(required_fields) #=> {u'status': u'string', u'name': u'string', u'account_id': u'int', u'start_date': u'datetime'}
    order = {
        'status': 'Active',
        'name': 'OX3APIClient Object Creation Test',
        'account_id': account_id,
        'start_date': datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S'),
    }
    
    # OX3APIClient methods accept dicts for data parameters.
    order = ox.post('/a/order', data=order)
    # print(order) #=> {u'id': 12345}
    print('Created order id %s' % order['id'])
    
    # Lets get all the details on the order we just created.
    order = ox.get('/a/order/%s' % order['id'])
    print(order)

# Log out.
ox.delete('/a/session')
