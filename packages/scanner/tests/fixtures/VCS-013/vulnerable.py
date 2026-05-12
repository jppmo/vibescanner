import requests
import ssl
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_data(url):
    response = requests.get(url, verify=False)
    return response.json()

def fetch_post(url, body):
    return requests.post(url, json=body, verify=False, timeout=10)

ctx = ssl._create_unverified_context()
ctx.check_hostname = False
