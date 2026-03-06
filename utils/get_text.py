# get_text.py

from utils.session_logic import get_response

def get_response_text(url: str):
    try:
        response = get_response(url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Request failed for {url}: {e}")
        return None