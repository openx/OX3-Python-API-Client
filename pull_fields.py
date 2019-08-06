import ox3apiclient
import logging
import requests
import json

ox = ox3apiclient.client_from_file().logon()

ox.logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ox.logger.addHandler(ch)

report = ox.get('/report/fields');
