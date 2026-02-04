# http_client.py

import requests
from bs4 import BeautifulSoup


class HttpClient:
    def get(self, url: str) -> str:
        res = requests.get(url, timeout=20)
        res.raise_for_status()
        return res.text

    def get_soup(self, url: str) -> BeautifulSoup:
        html = self.get(url)
        return BeautifulSoup(html, "html.parser")
