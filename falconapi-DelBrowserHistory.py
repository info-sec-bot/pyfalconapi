
import os
import time
import re
# Requires Crowdstrike falcon and falconpy python package

from falconpy import RealTimeResponse, RealTimeResponseAdmin, Hosts

# Do not hardcode API credentials!

RCLIENT_ID = os.environ['RCLIENTID']
RCLIENT_SECRET=os.environ['RCLIENT_SECRET']

CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET=os.environ['CLIENT_SECRET']

falcon = Hosts(client_id=CLIENT_ID,
               client_secret=CLIENT_SECRET
               )

# Must be valid hostname with sensor - case insensitivels
gethostname = input("Please enter hostname: ")
hostname = gethostname

aid = falcon.query_devices_by_filter(
                    filter=f"hostname:'{hostname}*'"
                    )["body"]["resources"][0]

id_list = aid  # Can also pass a list here: ['ID1', 'ID2', 'ID3']

newresponse = falcon.get_device_details_v2(ids=id_list)

# Iterate through keys
# print(newresponse["body"]["resources"][0])
# print(type(newresponse["body"]["resources"][0]))
# print(newresponse["body"]["resources"][0]["device_id"])

device_id = newresponse["body"]["resources"][0]["device_id"]

# Do not hardcode API credentials!
rtr = RealTimeResponse(client_id=RCLIENT_ID,
                               client_secret=RCLIENT_SECRET
                               )

response = rtr.init_session(device_id=device_id,)

# print(response)
# print(response["body"]["resources"][0]["session_id"])

session_id = response["body"]["resources"][0]["session_id"]

# Do not hardcode API credentials!
rtradm = RealTimeResponseAdmin(client_id=RCLIENT_ID,
                               client_secret=RCLIENT_SECRET
                               )
# Put Browsing History executable on host
print("Deleting BrowsingHistoryView.exe from host...")
putreq = rtradm.execute_admin_command(base_command="rm",
                                  command_string=f"rm 'BrowsingHistoryView.exe'",
                                  session_id=session_id,
                                  )
# print("Output of putreq==>")
# print(putreq)

# Put Browsing History executable on host
print("Deleting history.csv from host...")
rscript = rtradm.execute_admin_command(base_command="rm",
                                  command_string=f"rm 'history.csv'",
                                  session_id=session_id 
                                  )
# print("Output of rscript==>")
# print(rscript)

# Run ls command on host
print("Running the ls command on host...")
lsscript = rtradm.execute_admin_command(base_command="ls",
                                  command_string=f"ls",
                                  session_id=session_id,
                                  )
# Giving time for cloud request to generate

time.sleep(10)

# print("Output of lsscript")
# print(lsscript)

# print(type(lsscript))
# print(lsscript["body"]["resources"][0]["cloud_request_id"])

# Check the ls command output
lsresponse = rtr.check_command_status(cloud_request_id=lsscript["body"]["resources"][0]["cloud_request_id"])
print(lsresponse)
print(type(response))
print(lsresponse["body"]["resources"][0])

# Delete the session
print("Deleting session...")
rtr.delete_session(session_id)