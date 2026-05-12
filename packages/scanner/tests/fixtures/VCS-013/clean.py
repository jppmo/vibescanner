import requests
import ssl

def fetch_data(url):
    response = requests.get(url, verify=True)
    return response.json()

def fetch_with_ca_bundle(url):
    return requests.get(url, verify="/etc/ssl/certs/ca-certificates.crt")

ctx = ssl.create_default_context()
