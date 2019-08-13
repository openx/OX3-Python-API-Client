import ox3apiclient
import logging

ox = ox3apiclient.client_from_file().logon()

ox.logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ox.logger.addHandler(ch)

accounts = ox.get('/account')

report_get = ox.report_get('/data/1.0/report/fields')

report = {
"startDate": "20190709",
"endDate": "20190716",
"timezone": "UTC",
"attributes" :[
    {
      "id": "day"
    }
    ],
"metrics":[
    {"id": "marketRequests"
    }
    ]
}

report_out = ox.report_post('/data/1.0/report', data=report)


order = {
    'status': 'Active',
    'name': 'OX3APIClient Object Creation Test',
    'account_uid': accounts['objects'][0]['account_uid'],
    'start_date': '2016-06-01 00:00:00'}

new_order = ox.post('/order', data=order)

ox.delete('/order/%s' % new_order['uid'])

ox.logoff()
