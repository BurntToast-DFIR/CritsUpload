import requests
import json 

API_KEY = '72c6550ca9a83b1c502acca999356ae02763e2a2'

url = 'http://172.16.1.104:8080/api/v1/domains/'
params = {
'api_key': API_KEY,
'username': 'adove',
}
r = requests.get(url, params=params, verify=False)
j = json.loads(r.text)
print(r.json.im_self.content)

