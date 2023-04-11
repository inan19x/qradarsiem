# ref_set_dump.py
# IBM QRadar SIEM Reference Set object dump to a text file called 'ref_set_dump.txt'

import requests
import json
import datetime
import urllib3
import time
import shutil

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# QRadar SIEM
qradar              = {}
qradar['ip']        = 'x.x.x.x' #QRadar SIEM IP Address
qradar['ref_name']  = 'xxxxxxx' #QRadar SIEM Reference Set Name

# form the QRadar SIEM API url
url = "https://{0}/api/reference_data/sets/{1}".format(qradar['ip'], qradar['ref_name'])

payload = ""
headers = {
	'SEC': "xxxxxxxxxx-xxxxxxxxxxx-xxxxxxxx", #QRadar SIEM Auth Token
	}

refSetItem = []

#Got the list from QRadar SIEM Reference Set
response = requests.request("GET", url, data=payload, headers=headers, verify=False)
json_data = json.loads(response.text)
number_of_elements = json_data['number_of_elements']

if number_of_elements == 0:
	print('No data')
else:
	for items in json_data['data']:
		refSetItem.append(items['value'].encode('utf-8').strip('\n\r'))

with open('ref_set_dump.txt', 'w') as appendFile:
	if number_of_elements == 0:
		print('Write nothing')
		appendFile.write('')
	else:
		for newItem in refSetItem:
			appendFile.write(newItem+'\n')
