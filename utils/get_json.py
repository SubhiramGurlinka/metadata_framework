# get_json.py

from utils.session_logic import get_response

def get_json(url :str):
    try:
        response = get_response(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(e)
        return None