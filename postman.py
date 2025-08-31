import requests 


url = 'http://127.0.0.1:5000/api/v1/auth/register'
data = {
    'username':'iba200',
    'password':'ibt12345'
}


r = requests.post(url=url, json=data)

print(r.content)

"""
b'{"data":{"api_key":"ai_agent_B-Scz8gz5hZkRJg2duQ8eWlAlF_CULtnUiQUKAEW0Xc","role":"developer","user_id":"84f6e221-ed14-4888-91f4-2d46189c733c","username":"iba200"},"message":"Utilisateur cr\\u00e9\\u00e9 avec succ\\u00e8s","status":"success"}\n'
"""