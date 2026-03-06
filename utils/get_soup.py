# get_soup.py

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