# ref_set_checker.py
# IBM QRadar SIEM Reference Set objects reputation checker (and cleaner) by using IBM X-Force API as its lookup reference

import requests
import json
import requests.auth
import urllib3
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():

    # QRadar SIEM
    qradar              = {}
    qradar['payload']   = ''
    qradar['headers']   = {'SEC': 'xxxxxxxxxx-xxxxxxxxxxx-xxxxxxxx'} #QRadar SIEM Auth Token
    qradar['ip']        = 'x.x.x.x' #QRadar SIEM IP Address
    qradar['ref_set']   = {'xxx-Reference-Set-Name-xxx': 'ipr', 'xxx-Reference-Set-Name-xxx': 'url'}

    excluded_items      = []

    # X-Force
    xforce              = {} 
    xforce['key']       = 'xxxxxxxxxx-xxxxxxxxxxx-xxxxxxxx' #IBM X-Force Key
    xforce['password']  = 'xxxxxxxxxx-xxxxxxxxxxx-xxxxxxxx' #IBM X-Force Password/Secret
    xforce['headers']   = {'Accept': 'application/json', 'Accept-Language': 'en-US', 'Authorization': 'Basic'}
    xforce['url']       = 'https://api.xforce.ibmcloud.com/'

    # call the function
    maintain_ref_set(qradar, xforce, excluded_items)

def maintain_ref_set(qradar, xforce, excluded_items):

    for ref_name, xforce_url in qradar['ref_set'].items():

        print('Processing Reference Set {}'.format(ref_name))

        # store in array
        ref_set_data = []
        
        json_data = get_data_from_ref_set(qradar, ref_name)

        num_of_elements = json_data['number_of_elements']

        if num_of_elements == 0:
            print('No data')
        else:
            for item in json_data['data']:
                
                item_value = item['value']

                if item['value']:
                    item_value = item['value'].strip('\n\r')

                ref_set_data.append(item_value)

        counter = 0

        for item in ref_set_data:   
            if item in excluded_items:
                continue
                
            try: 
                json_data = check_item_in_xforce(xforce, xforce_url, item)
                score = 0
                
                if 'ipr' in xforce_url:
                    score = json_data.get('score')

                elif 'url' in xforce_url:

                    if 'result' in json_data:
                        reputation_info = json_data['result']
                        score           = reputation_info['score']
                
                print('Item: ' + item + ' has score ' + str(score))

                if score is None or (score >= 0 and score < 5):
                    print('Delete item ' + item + ' from Reference Set')

                    print(delete_item_from_ref_set(qradar, ref_name, item))
                else:
                    print('Keep item ' + item + ' on Reference Set')
                    
            except Exception as e:
                print(e)

            counter += 1

def get_data_from_ref_set(qradar, ref_name):
    # form the QRadar SIEM API url
    url         = 'https://{0}/api/reference_data/sets/{1}'.format(qradar['ip'], ref_name)
    response    = requests.request('GET', url, data=qradar['payload'], headers=qradar['headers'], verify=False)
    json_data   = json.loads(response.text)

    return json_data

def delete_item_from_ref_set(qradar, ref_name, item):
    # form the QRadar SIEM API url
    item = urllib.parse.quote(item, safe='')
    item = urllib.parse.quote(item, safe='')

    url         = 'https://{0}/api/reference_data/sets/{1}/{2}'.format(qradar['ip'], ref_name, item)
    response    = requests.request('DELETE', url, data=qradar['payload'], headers=qradar['headers'], verify=False)
    json_data   = json.loads(response.text)

    return json_data

def add_item_to_ref_set(qradar, ref_name, items):
    # form the QRadar SIEM API url
    url         = 'https://{0}/api/reference_data/sets/bulk_load/{1}'.format(qradar['ip'], ref_name)
    response    = requests.request('POST', url, data=json.dumps(items), headers=qradar['headers'], verify=False)
    json_data   = json.loads(response.text)
    print(json_data)
    return json_data

def check_item_in_xforce(xforce, sub_url, item):
    response = requests.get(xforce['url'] + sub_url + '/' + item, auth=(xforce['key'], xforce['password']), headers=xforce['headers'], verify=False)
    json_data = json.loads(response.content)

    return json_data

if __name__ == "__main__":
    main()