import requests

# url = "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant"
# headers = {
#     "User-Agent": "GarenaMSDK/4.0.41(SM-S908E ;Android 9;en;US;app 1.123.1 2019120270;)",
#     "Accept": "application/json",
#     "Content-Type": "application/json; charset=utf-8",
#     "Host": "ffmconnect.live.gop.garenanow.com",
#     "Connection": "Keep-Alive",
#     "Accept-Encoding": "gzip"
# }

# data = {
#     "client_id": 100067,
#     "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
#     "client_type": 2,
#     "password": "DCC7E9032E99EF4E6B791889F9BA5A4F7F5D53201E8FA6886F37CFC9A8255F6F",
#     "response_type": "token",
#     "uid": 4736616367
# }

# response = requests.post(url, headers=headers, json=data)
# response_json = response.json()
# print("Response Code:", response.status_code)
# print("UID:", response_json["data"]["uid"])
# print("Open ID:", response_json["data"]["open_id"])
# print("Access Token:", response_json["data"]["access_token"])

def get_oauth_token(uid, password):
    url = "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.41(SM-S908E ;Android 9;en;US;app 1.123.1 2019120270;)",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "ffmconnect.live.gop.garenanow.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    data = {
        "client_id": 100067,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2,
        "password": password,
        "response_type": "token",
        "uid": uid
    }

    response = requests.post(url, headers=headers, json=data)
    response_json = response.json()
    
    if response.status_code == 200:
        print("Response Code:", response.status_code)
        print("UID:", response_json["data"]["uid"])
        print("Open ID:", response_json["data"]["open_id"])
        print("Access Token:", response_json["data"]["access_token"])
        return response_json["data"]["access_token"], response_json["data"]["open_id"]
    else:
        print("Failed to retrieve token. Response Code:", response.status_code)
        print("Response Body:", response.text)
