#!/usr/bin/python3

import os

from falconpy import Hosts

CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET=os.environ['CLIENT_SECRET']

falcon = Hosts(client_id=CLIENT_ID,
               client_secret=CLIENT_SECRET
               )
falcon = Hosts(client_id=CLIENT_ID,
               client_secret=CLIENT_SECRET
               )

gethostname = input("Please enter hostname: ")
hostname = gethostname

aid = falcon.query_devices_by_filter(
                    filter=f"hostname:'{hostname}*'"
                    )["body"]["resources"][0]
id_list = aid  # Can also pass a list here: ['ID1', 'ID2', 'ID3']

newresponse = falcon.get_device_details_v2(ids=id_list)

# Iterate through keys
print(newresponse["body"]["resources"][0])
print(type(newresponse["body"]["resources"][0]))
for key in newresponse["body"]["resources"][0]:
    print(key)
user_input = input("Please enter detail: ")
print(newresponse["body"]["resources"][0]["hostname"])
print("You entered:", user_input)
print(newresponse["body"]["resources"][0][user_input])
