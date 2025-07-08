
import os
from falconpy import Alerts

CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET=os.environ['CLIENT_SECRET']

# Do not hardcode API credentials!
falcon = Alerts(client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET
                )

response = falcon.query_alerts_v1(
                                  limit=5
                                  )
print(response)

# for key in response["body"]["resources"]:
#     print(key)
print(type(response["body"]["resources"]))


id_list = response["body"]["resources"]  # Can also pass a list here: ['ID1', 'ID2', 'ID3']

response = falcon.get_alerts_v2(composite_ids=id_list, include_hidden=True)
print(response["body"]["resources"])

for key in response["body"]["resources"][0]:
    print(key)
for i in range(len(response["body"]["resources"])):

    print("======================================================================")    
    print("Composite id:",response["body"]["resources"][i]["composite_id"],"\n")
    print("Alert name: ",response["body"]["resources"][i]["display_name"],"\n")
    print("Alert description: ",response["body"]["resources"][i]["description"])
    print("Alert description: ",response["body"]["resources"][i]["severity_name"])
    try:
        print("Source IP Addresses: ",response["body"]["resources"][i]["source_ips"],"\n")
    except: ("print")
    try:
        print("Destination IP Addresses: ",response["body"]["resources"][i]["destination_ips"],"\n")
    except: ("print")
    print("Timestamp: ", response["body"]["resources"][i]["timestamp"],"\n")
    try:
        print("Effected User(s) : ",response["body"]["resources"][i]["usernames"],"\n")
    except: ("print")
    print("Status :",response["body"]["resources"][i]["status"],"\n")
    try:
        print("Comments : ",response["body"]["resources"][i]["comment"],"\n")
    except: ("print")
    print("Assigned to: ",response["body"]["resources"][i]["assigned_to_name"])

