import requests
from bs4 import BeautifulSoup

def get_soup(url :str, parser: str):
    try:
        response = requests.get(url, timeout = 15)
        response.raise_for_status()
        return BeautifulSoup(response.content, parser)

    except Exception as e:
        return e