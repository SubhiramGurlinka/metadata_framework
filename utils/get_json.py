# get_json.py

import requests

def get_json(url :str):
    try:
        response = requests.get(url, timeout= 15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(e)
        return None