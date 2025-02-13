import requests
import json

#ユーザ名・パスワード・サーバ名・ポート番号
username = "username"
password = "password"
server = "xxx.cybereason.net"
port = "443"

data = {
    "username": username,
    "password": password,
}

headers = {"Content-Type": "application/json"}
base_url = "https://" + server + ":" + port
login_url = base_url + "/login.html"

session = requests.session()
response = session.post(login_url, data=data, verify=True)

print (response.status_code)
print (session.cookies.items())

# Request URL
endpoint_url = "/rest/detection/inbox"
api_url = base_url + endpoint_url

# Unixエポックタイムスタンプ(ミリ秒)
start_time = 1680274800000 #2023/04/01 00:00
end_time = 1680534000000 #2023/04/04 00:00

query = json.dumps({"startTime":start_time,"endTime":end_time})

api_headers = {'Content-Type':'application/json'}

api_response = session.request("POST", api_url, data=query, headers=api_headers)

your_response = json.loads(api_response.content)

print(json.dumps(your_response, indent=4, sort_keys=True))
