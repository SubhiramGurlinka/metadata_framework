import requests

def get_response_text(url: str):
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.text
    
    except Exception as e:
        print(e)
        return None