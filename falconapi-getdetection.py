import os

from falconpy import Detects

CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET=os.environ['CLIENT_SECRET']


# Do not hardcode API credentials!
falcon = Detects(client_id=CLIENT_ID,
                 client_secret=CLIENT_SECRET
                 )

response = falcon.query_detects(
                                status="new",
                                sort="last_behavior|desc",
                                limit=5
                                )
# print(type(response["body"]["resources"]))
# print(response)

id_list = response["body"]["resources"]  # Can also pass a list here: ['ID1', 'ID2', 'ID3']

response = falcon.get_detect_summaries(ids=id_list)
print(response)
print(type(response))
for key in response["body"]["resources"]:
    print(key)

for key in response["body"]["resources"][0]["device"]:
    print(key)

for i in range(5):
    print(response["body"]["resources"][i]["device"])





