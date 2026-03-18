# get_page.py

from bs4 import BeautifulSoup
from utils.session_logic import get_response

def get_soup(url :str, parser: str):
    try:
        response = get_response(url)
        response.raise_for_status()
        return BeautifulSoup(response.content, parser)

    except Exception as e:
        print(e)
        return None

def get_json(url :str):
    try:
        response = get_response(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(e)
        return None

def get_response_text(url: str):
    try:
        response = get_response(url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Request failed for {url}: {e}")
        return None